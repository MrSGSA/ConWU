using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using StreamLink.Core;
using StreamLink.Discovery;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task CoordinatorPunchIntegration(bool reachable=false,string mode="mimic")
    {
        if(!WindowsInstance.IsValidation)WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));string root=Path.Combine(Path.GetTempPath(),"conwu-coordinator-punch-"+WindowsInstance.ValidationId+"-"+mode);Directory.CreateDirectory(root);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
        string pem=Path.Combine(root,"cert.pem"),secret=Path.Combine(root,"key.pem");File.WriteAllText(pem,certificate.ExportCertificatePem());File.WriteAllText(secret,key.ExportPkcs8PrivateKeyPem());
        await using var coordinator=CoordinationHost.Create(new(Path.Combine(root,"service"),"https://127.0.0.1:0",pem,secret));await coordinator.Start();
        string url=coordinator.Addresses.Single()+"/",pin=Convert.ToHexString(SHA256.HashData(certificate.RawData));
        var sessions=new PunchAssistSessions();int preparations=0,probes=0;WorkspaceNode? hostNode=null;
        PunchAssistClient Assist(bool guest)=>new(new HttpClient(new AssistGateway(sessions,guest?"8.8.4.4":"8.8.8.8")){BaseAddress=new Uri(url)},_=>Task.FromResult(new IPEndPoint(IPAddress.Parse("1.1.1.1"),1145)));
        using var host=hostNode=new WorkspaceNode(Path.Combine(root,"host"),"Assisted host",coordination:url,pin:pin,
            mappingFactory:()=>new AssistedMapping(),transportOverride:r=>r.Server?new AssistedIngress(()=>Interlocked.Increment(ref probes)):new ForwardingTransport(r.Target),
            configureRuntime:s=>s with{MimicPortSharing=true,TcpPortSharing=true,PunchAssistClient=(_,_,guest)=>Assist(guest)});
        using var unreachable=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        using var guest=new WorkspaceNode(Path.Combine(root,"guest"),"Assisted guest",host,
            transportOverride:r=>new ForwardingTransport(reachable?hostNode!.NativeTarget!:(IPEndPoint)unreachable.Client.LocalEndPoint!,toleratePeerOffline:true),
            configureRuntime:s=>s with{PunchAssistClient=(_,_,bootstrap)=>Assist(bootstrap),TcpPairClient=(_,_,_,_,_,_)=>{
                if(reachable)throw new InvalidOperationException("reachable hosts must not require guest STUN or UPnP");
                Interlocked.Increment(ref preparations);return Task.FromResult<IMappedMeshTransport>(new AssistedClient(hostNode!.NativeTarget!));
            }});
        try{
            var configuration=(await host.State()).Configurations.Single();
            var settings=configuration.Settings with{PathSelection=mode+"-only",ConnectionSource="custom",DirectMode=false,DiscoveryMode="coordinator",Service=url,CertificatePin=pin,ExistingEntries=[]};
            var saved=await host.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",configuration.Id,configuration.Name,configuration.Revision,settings)));Check(saved.Ok,saved.Error);
            var created=await host.Action("",new("create",Service:url,CertificatePin:pin,Mode:mode){LocalEnrollment=true,Name="Assisted pair",ConfigurationId=configuration.Id});Check(created.Ok,created.Error);
            string hostId=created.Status!.SelectedNetworkId;
            var issued=await host.Action(hostId,new("invite-compact",ExpectedNetwork:created.Status.NetworkId));Check(issued.Ok,issued.Error);
            var code=issued.Status!.Pairing!.Code;var decoded=CompactDirectCode.Import(code);
            Check(decoded.CoordinatorPunch&&decoded.Mode==mode&&decoded.Endpoint=="1.1.1.1:1145"&&sessions.Status.Waiting==1,"autonomous coordinated Mimic issues one sixteen-symbol helper code without exposing a stale host entry");
            var joined=await guest.Action("",new("join-compact",Code:code){AutoConfigure=true});Check(joined.Ok,joined.Error);string guestId=joined.Status!.SelectedNetworkId;
            Check(reachable?preparations==0&&probes==0:preparations==1&&probes==1,reachable
                ?"a reachable coordinated host pairs without any guest STUN/UPnP or assisted SYN"
                :"first enrollment prepares the guest source once and synchronizes one host probe");
            Check(!joined.Status.NetworkEnabled&&joined.Status.NetworkId.Length==0,"the helper cannot authorize a member or activate its network");
            UiPairingDto? pairing=null;
            for(int attempt=0;attempt<70;attempt++){
                await guest.Action(guestId,new("pair-poll"));await host.Action(hostId,new("pair-poll"));
                pairing=(await host.State()).Networks.Single(n=>n.Id==hostId).Status.Pairing;
                if(pairing?.Verification.Length==6)break;await Task.Delay(50);
            }
            Check(pairing?.Verification.Length==6,"direct committed-key exchange still produces the host's verification code");
            var refused=await host.Action(hostId,new("approve",ExpectedNetwork:created.Status.NetworkId,Verification:pairing!.Verification=="000000"?"000001":"000000",Candidate:pairing.Candidate));Check(!refused.Ok,"a wrong verification code cannot approve coordinated first contact");
            var approved=await host.Action(hostId,new("approve",ExpectedNetwork:created.Status.NetworkId,Verification:pairing.Verification,Candidate:pairing.Candidate,ProposedIp:pairing.ProposedIp));Check(approved.Ok,approved.Error);
            bool imported=false;
            for(int attempt=0;attempt<60;attempt++){var poll=await guest.Action(guestId,new("pair-poll"));Check(poll.Ok,poll.Error);imported=poll.Status!.NetworkId.Length>0;if(imported)break;await Task.Delay(50);}
            Check(imported,"only host approval downloads and saves the coordinated network policy");
            var received=(await guest.State()).Networks.Single(n=>n.Id==guestId).Status;
            Check(received.ReceivedNetworkSettings?.DiscoveryMode=="coordinator"&&received.Settings.ConnectionSource=="custom"&&received.Settings.Service==url,
                "the guest inherits autonomous coordination settings through the approved encrypted exchange");
            Check(received.Settings.ExistingEntries.All(e=>e.Source!="1.1.1.1:1145"),"a helper address never becomes a business entry or subscription");
        }finally{await guest.Worker.StopLocal();await host.Worker.StopLocal();}
        Console.WriteLine($"PASS {checks} coordinator first-contact integration checks; helper/source transport fixtures, real workers and approval");
    }
    sealed class AssistedMapping:IMimicSourceMapping
    {public IPAddress LocalAddress=>IPAddress.Loopback;public IPEndPoint LocalEndpoint=>new(IPAddress.Loopback,45200);public IPEndPoint PublicEndpoint=>new(IPAddress.Parse("8.8.8.8"),45200);public bool IsValid=>true;public event Action<IPEndPoint>? Changed{add{}remove{}}public Task Maintain(CancellationToken token)=>Task.Delay(Timeout.Infinite,token);public ValueTask DisposeAsync()=>ValueTask.CompletedTask;}
    sealed class AssistedIngress(Action probed):IMeshTransport,IMeshPunchTransport
    {public IPEndPoint? ClientEndpoint=>null;public bool Exited=>false;public void Dispose(){}public void Punch(IPEndPoint peer)=>probed();}
    sealed class AssistedClient(IPEndPoint target):IMappedMeshTransport,IMeshPunchTransport,IPairTransportIdentity
    {public string PeerCertificatePin=>StreamMeshTransport.CertificatePin(StreamTransportIdentity.Get());public StreamConnectionStatus? StreamConnection=>null;readonly ForwardingTransport forwarding=new(target);public IPEndPoint PublicEndpoint=>new(IPAddress.Parse("8.8.4.4"),45202);public IPEndPoint? ClientEndpoint=>forwarding.ClientEndpoint;public bool Exited=>forwarding.Exited;public void Dispose()=>forwarding.Dispose();public void Punch(IPEndPoint endpoint){} }
    sealed class AssistGateway(PunchAssistSessions sessions,string source):HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            if(request.Method==HttpMethod.Get)return new(HttpStatusCode.OK){Content=JsonContent.Create(new{punchAssist=1,punchTcpStun=1,punchModes=new[]{"faketcp","phantun","mimic","tcpraw","tcp","https"}})};
            string last=request.RequestUri!.Segments.Last();var address=IPAddress.Parse(source);PunchAssistState state;
            if(last=="create")state=sessions.Create((await request.Content!.ReadFromJsonAsync<PunchAssistCreate>(token))!,address);
            else if(last=="join")state=sessions.Join((await request.Content!.ReadFromJsonAsync<PunchAssistJoin>(token))!,address);
            else state=sessions.Update(last,(await request.Content!.ReadFromJsonAsync<PunchAssistUpdate>(token))!,address);
            return new(HttpStatusCode.OK){Content=JsonContent.Create(state)};
        }
    }
}
