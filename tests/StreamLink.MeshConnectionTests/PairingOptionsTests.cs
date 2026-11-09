using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task PairingOptions()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var preferences=new UiNetworkSettings{ConnectionSource="existing",DirectMode=true,DiscoveryMode="existing",ExistingEntries=[new(0,"203.0.113.1:44680")]};
        var original=new DeviceProfile();ConnectionSettings.Apply(original,ConnectionSettings.Normalize(preferences));
        var paired=ConnectionSettings.Normalize(preferences with{PairingService="https://pairing.example.com/",PairingCertificatePin=new string('a',64)});
        var changedProfile=ProfileChanges.Copy(original);ConnectionSettings.Apply(changedProfile,paired);
        Check(ProfileChanges.Impact(original,changedProfile)==ProfileChangeImpact.None&&changedProfile.CoordinationService.Length==0,"pairing-only settings change no data start parameter and require no network restart");
        Check(ConnectionSettings.PairingCoordinator(paired).Service==paired.PairingService,"existing-entry enrollment has an explicit independent pairing service");
        Check(ConnectionSettings.PairingCoordinator(paired with{ConnectionSource="custom",DiscoveryMode="pkarr"}).Service.Length==0,"dormant pairing preferences cannot enable coordination in a PKARR discovery strategy");
        foreach(string invalid in new[]{"http://example.com/","https://example.com/?token=hidden","https://user:secret@example.com/"}){
            bool rejected=false;try{ConnectionSettings.Normalize(preferences with{PairingService=invalid});}catch(FormatException){rejected=true;}
            Check(rejected,"pairing service rejects a non-HTTPS or credential-bearing URL");
        }
        string folder=Path.Combine(ProfileStore.Root,"pairing-options");Directory.CreateDirectory(folder);
        using var key=RSA.Create(2048);
        var request=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        using var certificate=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
        string certificatePath=Path.Combine(folder,"certificate.pem"),privatePath=Path.Combine(folder,"certificate-key.pem");
        File.WriteAllText(certificatePath,certificate.ExportCertificatePem());File.WriteAllText(privatePath,key.ExportPkcs8PrivateKeyPem());
        using var reservation=new TcpListener(IPAddress.Loopback,0);reservation.Start();int port=((IPEndPoint)reservation.LocalEndpoint).Port;reservation.Stop();
        string url=$"https://127.0.0.1:{port}/",pin=Convert.ToHexString(SHA256.HashData(certificate.RawData));
        using var coordinator=new WorkspaceNode(Path.Combine(folder,"coordinator"),"Coordinator",coordinator:new(true,url,certificatePath,privatePath));
        try{
            bool ready=false;for(int attempt=0;attempt<100;attempt++){ready=(await coordinator.State()).Coordinator?.Running==true;if(ready)break;await Task.Delay(30);}
            Check(ready,"pairing choices use the ordinary integrated ConWU HTTPS coordinator");
            foreach(string scenario in new[]{"autonomous-invitation","existing-code","existing-invitation-offline"}){
                bool existing=scenario.StartsWith("existing"),code=scenario=="existing-code";
                using var blackhole=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);blackhole.Bind(new IPEndPoint(IPAddress.Loopback,0));
                WorkspaceNode? guestTarget=null;
                IMeshTransport HostTransport(MeshTransportRequest r)=>r.Server?new StubTransport(null):new ForwardingTransport(guestTarget?.NativeTarget??(IPEndPoint)blackhole.LocalEndPoint!,toleratePeerOffline:true);
                var hostMapping=new Mapping();hostMapping.Change(new(IPAddress.Parse("203.0.113.54"),45460));
                var guestMapping=new Mapping();guestMapping.Change(new(IPAddress.Parse("203.0.113.55"),45461));
                using var host=new WorkspaceNode(Path.Combine(folder,scenario,"host"),"Host",mappingFactory:existing?null:()=>hostMapping,transportOverride:HostTransport);
                using var guest=new WorkspaceNode(Path.Combine(folder,scenario,"guest"),"Guest",host,mappingFactory:existing?null:()=>guestMapping);
                guestTarget=guest;
                try{
                    var config=(await host.State()).Configurations.Single();
                    var settings=config.Settings with{
                        ConnectionSource=existing?"existing":"custom",DirectMode=existing,DiscoveryMode=existing?"existing":"coordinator",
                        Service=existing?"":url,CertificatePin=existing?"":pin,PairingService=existing?url:"",PairingCertificatePin=existing?pin:"",CoordinatorBackup=false
                    };
                    var configured=await host.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",config.Id,config.Name,config.Revision,settings)));Check(configured.Ok,configured.Error);
                    var created=await host.Action("",new(existing?"create-direct":"create",Service:settings.Service,CertificatePin:settings.CertificatePin){Name=scenario,ConfigurationId=config.Id});Check(created.Ok,created.Error);
                    string hostId=created.Status!.SelectedNetworkId,network=created.Status.NetworkId;
                    await Until(()=>host.NativeTarget!=null,"selected strategy starts its actual loopback receiver");
                    var invited=await host.Action(hostId,new(code?"invite-code":"invite-direct",ExpectedNetwork:network));Check(invited.Ok,invited.Error);
                    if(!existing)Check(host.Probes>0,"generating a coordinated direct invitation prepares its autonomous entry on demand");
                    string locator=invited.Status!.Pairing!.Code;
                    if(code){
                        Check(locator.Length==6&&invited.Status.Pairing.Method=="code"&&invited.Status.Pairing.Service==url,"existing-entry owner generates six digits on the selected HTTPS service");
                        var active=(await host.State()).Configurations.Single();
                        var changed=await host.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",active.Id,active.Name,active.Revision,active.Settings with{PairingService="https://future-pairing.example.invalid/"})));Check(changed.Ok,changed.Error);
                        Check((await host.State()).Networks.Single().Status.Pairing?.Service==url,"a live code retains its original service when future pairing preferences change");
                    }
                    else{
                        var invitation=DirectPairInvitation.Import(locator);
                        Check((invitation.Service==null)==existing,"direct invitation preserves whether its network uses coordinated runtime discovery");
                        if(!existing){
                            Check(invitation.Service==url&&invitation.CertificatePin==pin,"coordinated invitation signs the server identity and certificate pin");
                            var forged=invitation with{Service="https://other.example.com/"};
                            bool rejected=false;try{DirectPairInvitation.Import("SL6."+Convert.ToBase64String(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(forged)));}catch(CryptographicException){rejected=true;}
                            Check(rejected,"changing the coordinated invitation's service invalidates its signature");
                            var stripped=invitation with{Service=null,CertificatePin=null};rejected=false;try{DirectPairInvitation.Import("SL6."+Convert.ToBase64String(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(stripped)));}catch(CryptographicException){rejected=true;}
                            Check(rejected,"stripping coordinated identity cannot downgrade a signed invitation to a serverless network");
                        }
                    }
                    var joined=await guest.Action("",new(code?"join":"join-invitation",Service:code?url:"",CertificatePin:code?pin:"",Code:locator){AutoConfigure=true});Check(joined.Ok,joined.Error);
                    string guestId=joined.Status!.SelectedNetworkId;UiPairingDto? pair=null;
                    for(int attempt=0;attempt<100;attempt++){
                        var hp=await host.Action(hostId,new("pair-poll"));Check(hp.Ok,hp.Error);
                        var gp=await guest.Action(guestId,new("pair-poll"));Check(gp.Ok,gp.Error);
                        pair=(await host.State()).Networks.Single().Status.Pairing;if(pair?.Verification.Length==6)break;await Task.Delay(30);
                    }
                    Check(pair?.Verification.Length==6&&(await guest.State()).Networks.Single().Status.ReceivedNetworkSettings==null,"either invitation carrier keeps settings private until verified approval");
                    var approved=await host.Action(hostId,new("approve",ExpectedNetwork:network,Verification:pair!.Verification,Candidate:pair.Candidate,ProposedIp:pair.ProposedIp));Check(approved.Ok,approved.Error);
                    bool imported=false;for(int attempt=0;attempt<100;attempt++){var poll=await guest.Action(guestId,new("pair-poll"));Check(poll.Ok,poll.Error);imported=poll.Status!.NetworkId==network;if(imported)break;await Task.Delay(30);}
                    Check(imported,"either carrier delivers the same approved network identity and automatic settings");
                    var saved=new ProfileStore(Path.Combine(guest.Store.DirectoryPath,"networks",guestId),guest.Store).LoadForMaintenance();
                    Check(saved.Mesh!.Pair.Direct==existing&&saved.ReceivedNetworkSettings!.ConnectionSource==settings.ConnectionSource,"pairing choice never rewrites the network's data discovery strategy");
                    if(existing)Check(host.Probes==0&&guest.Probes==0&&saved.CoordinationService.Length==0&&saved.Mesh.Pair.Service.Length==0&&!saved.SavedNetworkSettings!.CoordinatorBackup,"short-code coordination for existing entries starts no autonomous probe or runtime coordinator fallback");
                    if(code)Check(saved.SavedNetworkSettings!.PairingService==url,"approval binds the recipient to the service that actually carried its code rather than a newly edited preference");
                    var hs=await PairReady(host,18000,guest);var gs=(await guest.State()).Networks.Single();var hn=hs.Networks.Single();
                    guest.Adapters[network].Outgoing.Add(Packet(gs.Status.VirtualIp,hn.Status.VirtualIp));
                    bool delivered=false;for(int attempt=0;attempt<100;attempt++){delivered=(await host.State()).Aggregate!.ReceivedBytes==1280;if(delivered)break;await Task.Delay(30);}
                    Check(delivered,"approved network carries the single inner packet over its authenticated loopback data channel");
                    if(code){await coordinator.Worker.StopLocal();Check((await coordinator.State()).Networks.Length==0,"pairing coordinator does not enroll itself as a network member");}
                    if(scenario.EndsWith("offline")){
                        var current=(await host.State()).Configurations.Single();int receivers=host.Servers;
                        var cleared=await host.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",current.Id,current.Name,current.Revision,current.Settings with{PairingService=""})));Check(cleared.Ok,cleared.Error);
                        var unavailable=await host.Action(hostId,new("invite-code",ExpectedNetwork:network));Check(!unavailable.Ok&&unavailable.Error.Contains("协调服务器"),"without a configured pairing service the owner cannot advertise an undiscoverable six-digit code");
                        Check(host.Servers==receivers&&(await host.State()).Networks.Single().Status.DirectPeers==1,"changing pairing-only settings preserves the healthy data receiver and connection");
                        var noServer=await host.Action("",new("create-direct"){Name="Invitation only",ConfigurationId=current.Id});Check(noServer.Ok,noServer.Error);
                        Check(noServer.Status!.Pairing?.Active!=true&&string.IsNullOrEmpty(noServer.Status.Pairing?.Code),"new explicit serverless configurations create no hidden numeric pairing room");
                    }
                }finally{await Task.WhenAll(host.Worker.StopLocal(),guest.Worker.StopLocal());}
            }
        }finally{await coordinator.Worker.StopLocal();}
        Console.WriteLine($"PASS {checks} independent pairing-choice checks; actual local TLS coordinator and loopback transport, no physical NAT claim");
    }
}
