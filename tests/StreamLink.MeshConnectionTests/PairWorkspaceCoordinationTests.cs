using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task PairWorkspaceCoordination(bool automatic=false,bool directEntries=false)
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));string folder=Path.Combine(ProfileStore.Root,"coordinated-pairs");Directory.CreateDirectory(folder);
        using var key=RSA.Create(2048);var request=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        using var certificate=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(2));
        string certificatePath=Path.Combine(folder,"certificate.pem"),privatePath=Path.Combine(folder,"certificate-key.pem");
        File.WriteAllText(certificatePath,certificate.ExportCertificatePem());File.WriteAllText(privatePath,key.ExportPkcs8PrivateKeyPem());
        using var reservation=new TcpListener(IPAddress.Loopback,0);reservation.Start();int port=((IPEndPoint)reservation.LocalEndpoint).Port;reservation.Stop();
        string url=$"https://127.0.0.1:{port}/",pin=Convert.ToHexString(SHA256.HashData(certificate.RawData));
        using var coordinator=new WorkspaceNode(Path.Combine(folder,"coordinator"),"Coordinator",coordinator:new(true,url,certificatePath,privatePath));
        using var host=new WorkspaceNode(Path.Combine(folder,"host"),"Coordinated host",coordination:url,pin:pin);
        using var first=new WorkspaceNode(Path.Combine(folder,"first"),"Coordinated first",host,url,pin);
        using var second=new WorkspaceNode(Path.Combine(folder,"second"),"Coordinated second",host,url,pin);
        try{
            bool ready=false;for(int attempt=0;attempt<100;attempt++){ready=(await coordinator.State()).Coordinator?.Running==true;if(ready)break;await Task.Delay(50);}
            Check(ready,"the ordinary ConWU device hosts the actual HTTPS coordination service");
            if(directEntries){var config=(await host.State()).Configurations.Single();var update=await host.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",config.Id,config.Name,config.Revision,config.Settings with{DirectMode=true,CoordinatorBackup=true})));Check(update.Ok,update.Error);}
            async Task<string> Connect(WorkspaceNode guest,string name)
            {
                var created=await host.Action("",new(directEntries?"create-direct":"create",Service:url,CertificatePin:pin){Name=name});Check(created.Ok,created.Error);
                Check(created.Status!.Pairing?.Code.Length==6,"host creates an expiring short code on the shared HTTPS service");
                string hostId=created.Status.SelectedNetworkId;
                var joining=await guest.Action("",new("join",Service:url,CertificatePin:pin,Code:created.Status.Pairing!.Code){Name=name,AutoConfigure=automatic});Check(joining.Ok,joining.Error);
                string guestId=joining.Status!.SelectedNetworkId;UiPairingDto? pairing=null;
                for(int attempt=0;attempt<80;attempt++){
                    await host.Action(hostId,new("pair-poll"));await guest.Action(guestId,new("pair-poll"));
                    pairing=(await host.State()).Networks.Single(n=>n.Id==hostId).Status.Pairing;
                    if(pairing?.Verification.Length==6)break;await Task.Delay(50);
                }
                Check(pairing?.Verification.Length==6,"HTTPS pairing preserves committed keys and stable device identity");
                var approved=await host.Action(hostId,new("approve",ExpectedNetwork:created.Status.NetworkId,Verification:pairing!.Verification,Candidate:pairing.Candidate,ProposedIp:pairing.ProposedIp));Check(approved.Ok,approved.Error);
                bool imported=false;for(int attempt=0;attempt<60;attempt++){var poll=await guest.Action(guestId,new("pair-poll"));Check(poll.Ok,poll.Error);imported=poll.Status!.NetworkId.Length>0;if(imported)break;await Task.Delay(50);}
                Check(imported,"HTTPS approval delivers a signed two-device enrollment");
                if(automatic){var status=(await guest.State()).Networks.Single(n=>n.Id==guestId);Check(status.ConfigurationId.Length==0&&status.Status.ReceivedNetworkSettings!=null,"automatic HTTPS join receives host settings without attaching a client configuration");}
                return guestId;
            }
            string firstId=await Connect(first,"First HTTPS pair"),secondId=await Connect(second,"Second HTTPS pair");
            UiStatusDto hs=await host.State();for(int attempt=0;attempt<180&&hs.Aggregate!.ConnectedNetworks!=2;attempt++){await Task.Delay(100);hs=await host.State();}
            if(hs.Aggregate!.ConnectedNetworks!=2)foreach(var network in hs.Networks)foreach(var log in network.Status.Logs)Console.WriteLine(log);
            Check(hs.Aggregate.ConnectedNetworks==2&&host.Servers==1,"one shared coordination service establishes two direct links on one shared receiver");
            Check((await coordinator.State()).Networks.Length==0&&coordinator.Adapters.IsEmpty,"coordination alone never joins client networks or allocates a virtual adapter");
            var firstState=(await first.State()).Networks.Single(n=>n.Id==firstId);var hostFirst=hs.Networks.Single(n=>n.Status.NetworkId==firstState.Status.NetworkId);
            var secondState=(await second.State()).Networks.Single(n=>n.Id==secondId);var hostSecond=hs.Networks.Single(n=>n.Status.NetworkId==secondState.Status.NetworkId);
            await coordinator.Worker.StopLocal();
            first.Adapters[firstState.Status.NetworkId].Outgoing.Add(Packet(firstState.Status.VirtualIp,hostFirst.Status.VirtualIp));
            second.Adapters[secondState.Status.NetworkId].Outgoing.Add(Packet(secondState.Status.VirtualIp,hostSecond.Status.VirtualIp));
            bool delivered=false;for(int attempt=0;attempt<80;attempt++){delivered=(await host.State()).Aggregate!.Peers.All(p=>p.Peer.ReceivedBytes>=1280);if(delivered)break;await Task.Delay(50);}
            Check(delivered,"HTTPS coordination outage does not interrupt either authenticated data path");
            var timer=Stopwatch.StartNew();var exited=await first.Action(firstId,new("forget-network",ExpectedNetwork:firstState.Status.NetworkId,ConfirmReplace:true));
            Check(exited.Ok&&timer.Elapsed<TimeSpan.FromSeconds(3),"local exit remains prompt while the real HTTPS coordinator is unavailable");
            Check((await second.State()).Networks.Single(n=>n.Id==secondId).Status.DirectPeers==1,"one guest's exit leaves the other coordinated pair running");
        }finally{await Task.WhenAll(host.Worker.StopLocal(),first.Worker.StopLocal(),second.Worker.StopLocal(),coordinator.Worker.StopLocal());}
        Console.WriteLine($"PASS {checks} integrated HTTPS pair coordination checks; isolated TLS and loopback data transports");
    }
}
