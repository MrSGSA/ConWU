using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task CompactInvitationIntegration()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        string folder=Path.Combine(ProfileStore.Root,"compact-invitations");Directory.CreateDirectory(folder);
        using var key=RSA.Create(2048);var request=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        using var cert=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
        string certificate=Path.Combine(folder,"certificate.pem"),privateKey=Path.Combine(folder,"private.pem");File.WriteAllText(certificate,cert.ExportCertificatePem());File.WriteAllText(privateKey,key.ExportPkcs8PrivateKeyPem());
        using var reservation=new TcpListener(IPAddress.Loopback,0);reservation.Start();int port=((IPEndPoint)reservation.LocalEndpoint).Port;reservation.Stop();
        string service=$"https://127.0.0.1:{port}/",pin=Convert.ToHexString(SHA256.HashData(cert.RawData));
        using var coordinator=new WorkspaceNode(Path.Combine(folder,"coordinator"),"Coordinator",coordinator:new(true,service,certificate,privateKey));
        bool ready=false;for(int i=0;i<100;i++){ready=(await coordinator.State()).Coordinator?.Running==true;if(ready)break;await Task.Delay(30);}Check(ready,"compact pairing fixture has a real TLS coordinator for the configured-policy case");
        using var gateway=new PublishingGateway();using var http=new HttpClient(gateway);PkarrClient PkarrFactory()=>new(http,["https://fixture.invalid"]);
        foreach(string scenario in new[]{"existing-faketcp","existing-offline-pairing","autonomous-direct","autonomous-coordinated","autonomous-pkarr","existing-udp"}){
            bool existing=scenario.StartsWith("existing"),coordinated=scenario=="autonomous-coordinated",pkarr=scenario=="autonomous-pkarr";
            string mode=scenario.EndsWith("udp")?"udp":"faketcp",source=existing?"https://entry.example.invalid/current?token=read-only#streamlink1":"203.0.113.99:9999";
            using var blackhole=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);blackhole.Bind(new IPEndPoint(IPAddress.Loopback,0));
            WorkspaceNode? guestTarget=null;
            IMeshTransport HostTransport(MeshTransportRequest r)=>r.Server?new StubTransport(null):new ForwardingTransport(guestTarget?.NativeTarget??(IPEndPoint)blackhole.LocalEndPoint!,toleratePeerOffline:true);
            var mapping=new Mapping();mapping.Change(new(IPAddress.Parse("203.0.113.54"),45460));
            using var host=new WorkspaceNode(Path.Combine(folder,scenario,"host"),"Host",mappingFactory:existing?null:()=>mapping,transportOverride:HostTransport,pkarrFactory:pkarr?PkarrFactory:null);
            using var guest=new WorkspaceNode(Path.Combine(folder,scenario,"guest"),"Guest",host,mappingFactory:existing?null:()=>new PreparedMapping(),pkarrFactory:pkarr?PkarrFactory:null);guestTarget=guest;
            try{
                var config=(await host.State()).Configurations.Single();
                var settings=config.Settings with{ConnectionSource=existing?"existing":"custom",DirectMode=!coordinated,DiscoveryMode=existing?"existing":coordinated?"coordinator":pkarr?"pkarr":"direct",Service=coordinated?service:"",CertificatePin=coordinated?pin:"",PairingService=scenario=="existing-offline-pairing"?"https://127.0.0.1:1/":"",ExistingEntries=[new(0,source)],PathSelection=mode=="udp"?"udp-only":"faketcp-only",CoordinatorBackup=false};
                var saved=await host.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",config.Id,config.Name,config.Revision,settings)));Check(saved.Ok,saved.Error);
                var created=await host.Action("",new(coordinated?"create":"create-direct",Service:settings.Service,CertificatePin:settings.CertificatePin,Mode:mode){Name=scenario,ConfigurationId=config.Id});Check(created.Ok,created.Error);
                string hostId=created.Status!.SelectedNetworkId,network=created.Status.NetworkId;
                await Until(()=>host.NativeTarget!=null,"compact host starts its selected receiver without replacing its network");
                if(pkarr)await Until(()=>gateway.Packets.Count==1,"the isolated PKARR gateway has accepted the host announcement before reconnect assertions",18000);
                var issued=await host.Action(hostId,new("invite-compact",ExpectedNetwork:network));Check(issued.Ok,issued.Error);
                string code=issued.Status!.Pairing!.Code;var compact=CompactDirectCode.Import(code);
                Check(code.Length==19&&issued.Status.Pairing.Format=="compact"&&issued.Status.Pairing.Service.Length==0&&compact.Mode==mode,"compact generation contains sixteen symbols and no pairing-server dependency");
                Check((await host.State()).Networks.Single().Status.TotalPeers==0,"generating a compact code issues no membership");
                string wrong=(code[0]=='0'?'1':'0')+code[1..];
                var malformed=await guest.Action("",new("join-compact",Code:wrong){AutoConfigure=true});
                Check(!malformed.Ok&&(await guest.State()).Networks.Length==0,"a mistyped code is rejected without reserving a guest network");
                if(scenario=="existing-faketcp"){
                    host.ResolutionError="fixture subscription temporarily unavailable";
                    var unavailable=await host.Action(hostId,new("invite-compact",ExpectedNetwork:network));
                    var unchanged=(await host.State()).Networks.Single();
                    Check(!unavailable.Ok&&unchanged.Status.NetworkId==network&&unchanged.Status.Pairing is {Active:true} current&&current.Code==code,"a failed source refresh preserves the previous invitation and network");host.ResolutionError=null;
                    foreach(bool cancel in new[]{false,true}){
                        var pending=await guest.Action("",new("join-compact",Code:code){AutoConfigure=true});Check(pending.Ok,"a retained compact code still accepts a pending applicant: "+pending.Error);string pendingId=pending.Status!.SelectedNetworkId;
                        UiPairingDto? candidate=null;
                        for(int i=0;i<100;i++){await host.Action(hostId,new("pair-poll"));candidate=(await host.State()).Networks.Single().Status.Pairing;if(candidate?.Candidate.Length>0)break;await Task.Delay(30);}
                        Check(candidate?.Candidate.Length>0,"compact applicant reaches its explicit host room before cancellation or rejection");
                        if(cancel){var cancelled=await guest.Action(pendingId,new("pair-cancel"));Check(cancelled.Ok&&(await guest.State()).Networks.Length==0,"cancelling a compact request removes the unjoined context and frees its input");await host.Action(hostId,new("pair-poll"));}
                        else{var declined=await host.Action(hostId,new("reject",ExpectedNetwork:network,Candidate:candidate!.Candidate));Check(declined.Ok,"the host can reject a compact applicant: "+declined.Error);await guest.Action(pendingId,new("pair-poll"));Check((await guest.State()).Networks.Single().Status.Pairing?.Active!=true,"rejection clears the guest waiting state without issuing credentials");await guest.Action(pendingId,new("pair-cancel"));}
                        Check((await host.State()).Networks.Single().Status.TotalPeers==0,"cancelled and rejected compact applicants never receive network membership");
                        var regenerated=await host.Action(hostId,new("invite-compact",ExpectedNetwork:network));Check(regenerated.Ok,"compact pairing can be regenerated and retried: "+regenerated.Error);code=regenerated.Status!.Pairing!.Code;
                    }
                }
                var joined=await guest.Action("",new("join-compact",Code:" "+code.ToLowerInvariant().Replace('-',' ')+" "){AutoConfigure=true});Check(joined.Ok,joined.Error);
                string guestId=joined.Status!.SelectedNetworkId;Check(joined.Status.Pairing?.Format=="compact","guest status retains the compact-code carrier for passive UI observation");
                UiPairingDto? pair=null;
                for(int i=0;i<100;i++){var hp=await host.Action(hostId,new("pair-poll"));Check(hp.Ok,hp.Error);var gp=await guest.Action(guestId,new("pair-poll"));Check(gp.Ok,gp.Error);pair=(await host.State()).Networks.Single().Status.Pairing;if(pair?.Verification.Length==6)break;await Task.Delay(30);}
                Check(pair?.Verification.Length==6&&(await guest.State()).Networks.Single().Status.ReceivedNetworkSettings==null,"compact clients receive no configuration or member credentials before verification and approval");
                string incorrect=pair!.Verification=="000000"?"000001":"000000";
                var rejected=await host.Action(hostId,new("approve",ExpectedNetwork:network,Verification:incorrect,Candidate:pair.Candidate,ProposedIp:pair.ProposedIp));
                Check(!rejected.Ok&&(await host.State()).Networks.Single().Status.TotalPeers==0,"wrong SAS cannot authorize a compact-code applicant");
                var approved=await host.Action(hostId,new("approve",ExpectedNetwork:network,Verification:pair.Verification,Candidate:pair.Candidate,ProposedIp:pair.ProposedIp));Check(approved.Ok,approved.Error);
                bool imported=false;for(int i=0;i<100;i++){var poll=await guest.Action(guestId,new("pair-poll"));Check(poll.Ok,poll.Error);imported=poll.Status!.NetworkId==network;if(imported)break;await Task.Delay(30);}Check(imported,"compact approval delivers the original network identity");
                var received=new ProfileStore(Path.Combine(guest.Store.DirectoryPath,"networks",guestId),guest.Store).LoadForMaintenance();
                Check(received.SavedNetworkSettings!.ConnectionSource==settings.ConnectionSource&&received.SavedNetworkSettings.DiscoveryMode==settings.DiscoveryMode&&received.Mesh!.Pair.Direct==!coordinated,"compact joining preserves the host discovery policy instead of silently changing the network");
                Check(received.PathSelection==(mode=="udp"?"udp-only":"faketcp-only"),"the encoded protocol is applied explicitly with no fallback");
                if(existing)Check(received.SavedNetworkSettings.ExistingEntries.Any(e=>e.Source==source)&&host.Probes==0&&guest.Probes==0,"original subscription sources arrive after approval and existing entries never start autonomous punching");
                if(pkarr)Check(received.PkarrSeed.Length==0&&received.ExistingEntries.Any(e=>e.Source.StartsWith("pkarr://")),"PKARR discovery hints arrive after compact approval without disclosing the host publishing key");
                var hs=await PairReady(host,20000,guest);var gs=(await guest.State()).Networks.Single();
                guest.Adapters[network].Outgoing.Add(Packet(gs.Status.VirtualIp,hs.Networks.Single().Status.VirtualIp));
                bool delivered=false;for(int i=0;i<100;i++){delivered=(await host.State()).Aggregate!.ReceivedBytes>=1280;if(delivered)break;await Task.Delay(30);}Check(delivered,"the approved compact relation carries one authenticated inner packet");
            }finally{await guest.Worker.StopLocal();await host.Worker.StopLocal();}
        }
        // Compact codes reuse this room implementation, including its expiry,
        // approved-reply delivery reservation and unauthenticated reply limits.
        await DirectShortPairing();
        Console.WriteLine($"PASS {checks} compact invitation integration checks; isolated TLS and loopback transports, no physical streaming");
    }
}
