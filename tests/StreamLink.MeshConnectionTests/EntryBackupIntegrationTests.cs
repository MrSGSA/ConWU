using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using StreamLink.Core;
using StreamLink.Discovery;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task EntryBackupIntegration()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        string folder=Path.Combine(ProfileStore.Root,"backup-integration");Directory.CreateDirectory(folder);
        using var key=RSA.Create(2048);var request=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        using var cert=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
        string certFile=Path.Combine(folder,"cert.pem"),keyFile=Path.Combine(folder,"key.pem");File.WriteAllText(certFile,cert.ExportCertificatePem());File.WriteAllText(keyFile,key.ExportPkcs8PrivateKeyPem());
        await using var coordinator=CoordinationHost.Create(new(Path.Combine(folder,"coordinator"),"https://127.0.0.1:0",certFile,keyFile));await coordinator.Start();
        string url=coordinator.Addresses.Single()+"/",pin=Convert.ToHexString(SHA256.HashData(cert.RawData));
        using var host=new WorkspaceNode(Path.Combine(folder,"host"),"Backup host");
        int rejectedPrimary=0;
        using var guest=new WorkspaceNode(Path.Combine(folder,"guest"),"Backup guest",host,transportOverride:r=>{
            if(r.Server)return new StubTransport(null);
            if(r.Target.Address.ToString()=="198.51.100.20"){Interlocked.Increment(ref rejectedPrimary);return new StubTransport(null);}
            return new ForwardingTransport(host.NativeTarget??r.Target,toleratePeerOffline:true);
        });
        async Task Configure(WorkspaceNode node,bool target){
            var c=(await node.State()).Configurations.Single();
            var settings=c.Settings with{CoordinatorBackup=true,Service=url,CertificatePin=pin,ExistingEntries=[new(target?ExistingEntry.NetworkOwner:0,target?"198.51.100.20:45200":"203.0.113.1:45200")]};
            var saved=await node.Ui(new("configuration",Configuration:new("save",c.Id,c.Name,c.Revision,settings,true)));Check(saved.Ok,saved.Error);
        }
        async Task<UiControlReply> Act(WorkspaceNode node,string id,UiNetworkAction action){
            var op=Guid.NewGuid();var reply=await node.Ui(new("network",OperationId:op,Network:action){NetworkId=id});
            var timer=System.Diagnostics.Stopwatch.StartNew();
            while(reply.Ok&&reply.Operation is {Completed:false}){if(timer.Elapsed.TotalSeconds>70)throw new Exception("controlled operation timed out");await Task.Delay(100);reply=await node.Ui(new("status",OperationId:op){NetworkId=id});}
            Check(reply.Ok&&reply.Operation?.Error.Length is not >0,reply.Error+reply.Operation?.Error);return reply;
        }
        try{
            await Configure(host,false);await Configure(guest,true);
            var created=await Act(host,"",new("create-direct"){Name="Direct first with backup"});string hostId=created.Status!.SelectedNetworkId,code=created.Status.Pairing!.Code;
            await Until(()=>host.NativeTarget!=null,"direct listener starts before backup lookup");
            var joined=await Act(guest,"",new("join-direct-short",Code:code));string guestId=joined.Status!.SelectedNetworkId;
            Check(rejectedPrimary>0,"configured unreachable entry is tried before consulting the coordinator");
            UiPairingDto? pending=null;
            for(int i=0;i<100;i++){
                await Act(host,hostId,new("pair-poll"));await Act(guest,guestId,new("pair-poll"));
                pending=(await host.State()).Networks.Single(n=>n.Id==hostId).Status.Pairing;
                if(pending?.Verification.Length==6)break;await Task.Delay(50);
            }
            Check(pending?.Verification.Length==6,"backup address reaches the original direct room and requires host approval");
            Check((await host.State()).Networks.Single().Status.TotalPeers==0,"backup lookup alone cannot enroll a member");
            await Act(host,hostId,new("approve",ExpectedNetwork:created.Status.NetworkId,Verification:pending!.Verification,Candidate:pending.Candidate,ProposedIp:pending.ProposedIp));
            for(int i=0;i<80;i++){
                var polled=await Act(guest,guestId,new("pair-poll"));if(polled.Status!.NetworkId.Length>0)break;await Task.Delay(50);
            }
            var guestState=(await guest.State()).Networks.Single().Status;
            Check(guestState.NetworkDirect&&guestState.NetworkId==created.Status.NetworkId,"fallback changes address source without creating a second or coordinated network");
            var guestSettings=(await guest.State()).Configurations.Single().Settings;
            Check(guestSettings.CoordinatorBackup&&guestSettings.Service==url&&guestSettings.CertificatePin==pin,"direct enrollment retains the saved backup settings");
            await PairReady(host,15000,guest);
            Check((await host.State()).Aggregate!.ConnectedNetworks==1,"approved pair authenticates a direct data path after backup lookup");
            var hostState=(await host.State()).Networks.Single().Status;
            guest.Adapters[guestState.NetworkId].Outgoing.Add(Packet(guestState.VirtualIp,hostState.VirtualIp));
            bool delivered=false;for(int i=0;i<80;i++){delivered=(await host.State()).Aggregate!.Peers.Any(p=>p.Peer.ReceivedBytes>=1280);if(delivered)break;await Task.Delay(50);}
            Check(delivered,"data crosses the controlled direct path after fallback enrollment");
            Check(host.Probes==0&&guest.Probes==0,"neither address fallback nor metadata replication starts autonomous punching");
        }catch{foreach(var row in (await host.State()).Networks)foreach(var line in row.Status.Logs)Console.WriteLine(line);throw;}
        finally{await guest.Worker.StopLocal();await host.Worker.StopLocal();}
    }
}
