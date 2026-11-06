using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using StreamLink.Core;
using StreamLink.Service;
using StreamLink.Discovery;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    static async Task CoordinationFaults()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        using var signing=RSA.Create(2048);
        var request=new CertificateRequest("CN=localhost",signing,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        using var generated=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
        using var cert=X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx),null);
        var builder=WebApplication.CreateSlimBuilder();builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(o=>o.Listen(IPAddress.Loopback,0,l=>l.UseHttps(cert)));
        await using var app=builder.Build();bool unavailable=true,stall=false;int creates=0;
        string registryRoot=Path.Combine(ProfileStore.Root,"coordinator");Directory.CreateDirectory(registryRoot);var registry=new MeshRegistry(registryRoot);
        app.MapGet("/v3/mesh/{network}",(HttpContext c,string network)=>registry.Read(c,network));
        app.MapPut("/v4/mesh/{network}/membership",(HttpContext c,string network,MeshMembershipRequest change)=>registry.Membership(c,network,change));
        app.MapGet("/health",()=>unavailable?Results.StatusCode(503):Results.Json(new{meshProtocol=4,pairingDecisions=1,meshAddressing=1,memberRejoin=1,meshGovernance=1}));
        app.MapPost("/v2/pair",async(PairRoomCreate input,HttpContext context)=>{
            Interlocked.Increment(ref creates);
            if(stall)await Task.Delay(Timeout.Infinite,context.RequestAborted);
            return Results.Json(new PairRoomTicket(Guid.NewGuid().ToString("N"),"123456",Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),input.Commitment,input.Name,DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()));
        });
        app.MapDelete("/v2/pair/{room}",()=>Results.Json(new{closed=true}));
        await app.StartAsync();
        string address=app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single()+"/";
        string pin=Convert.ToHexString(SHA256.HashData(cert.RawData));
        var store=new ProfileStore();store.Save(new DeviceProfile{DeviceName="Fault-Client",Enabled=false,CoordinationService=address,CoordinationPin=pin,ConnectionSource="existing",EntryRefreshSeconds=120,ExistingEntries=[new(ExistingEntry.NetworkOwner,"203.0.113.24:44680")]});
        string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        var services=new MeshRuntimeServices(m=>new OwnerOnlyDiscovery(m),_=>Task.FromResult<IPacketAdapter>(new MemoryAdapter()),
            (_,_,_)=>Task.FromException<IMapping>(new IOException("isolated test has no gateway")),_=>throw new IOException("no peer in fixture"),
            (_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},Path.Combine(ProfileStore.Root,"sessions")){
            Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(null),NetworkWake=()=>new MeshNetworkWake(false)
        };
        using var worker=new ControlWorker(services);worker.StartLocal();
        Task<UiControlReply> Create()=>worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("create",Service:address,CertificatePin:pin)),sid,default);
        string savedSettings=JsonSerializer.Serialize((await worker.HandleUi(new("status"),sid,default)).Status!.Settings);
        try{
            var failedHealth=await Create();
            Check(!failedHealth.Ok&&failedHealth.Error.Contains("503")&&store.Load().Mesh==null&&creates==0,"unavailable HTTPS coordination fails before any network or invitation is committed: "+failedHealth.Error);
            Check(JsonSerializer.Serialize(failedHealth.Status!.Settings)==savedSettings,"failed coordination health check preserves all saved settings");
            unavailable=false;stall=true;
            var timeout=await Create();
            Check(timeout.Ok&&timeout.Status!.Logs.Any(l=>l.Contains("网络已创建")&&l.Contains("配对码")),"invitation timeout reports the already committed network accurately: "+timeout.Error+" | "+string.Join(" / ",timeout.Status!.Logs));
            Check(store.Load().Mesh is {IsDecentralized:true}&&store.Load().Enabled&&!timeout.Status!.Pairing!.Active,"lost invitation response keeps the committed network with no live pairing UI");
            Check(JsonSerializer.Serialize(timeout.Status!.Settings)==savedSettings,"actual coordination request timeout preserves saved settings");
            stall=false;var retry=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("invite",ExpectedNetwork:store.Load().Mesh!.Pair.Network)),sid,default);
            Check(retry.Ok&&store.Load().Mesh is {IsOwner:true}&&store.Load().Enabled,"retry creates and starts a complete network after coordination recovers");
            Check(creates==2&&retry.Status!.Pairing!.Active,"successful retry allocates one new invitation with no duplicate submit");
            Check(JsonSerializer.Serialize(retry.Status!.Settings)==savedSettings,"actual network creation preserves target entries and the complete saved settings");
            string oldNetwork=retry.Status.NetworkId;
            var removed=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("delete-network",ExpectedNetwork:oldNetwork,ConfirmReplace:true)),sid,default);
            Check(removed.Ok&&removed.Status!.NetworkId.Length==0&&JsonSerializer.Serialize(removed.Status.Settings)==savedSettings,"actual owner deletion preserves every saved setting");
            var recreated=await Create();
            Check(recreated.Ok&&recreated.Status!.NetworkId!=oldNetwork&&JsonSerializer.Serialize(recreated.Status.Settings)==savedSettings,"actual recreation creates a new network without resetting saved settings");
        }finally{await worker.StopLocal();await app.StopAsync();}
    }

    sealed class OwnerOnlyDiscovery(MeshProfile mesh):IMeshDiscovery
    {
        public Task SaveDirectory(MeshDirectory directory,CancellationToken token){mesh.Directory=directory;return Task.CompletedTask;}
        public Task Publish(MeshAnnouncement announcement,CancellationToken token)=>Task.CompletedTask;
        public Task<MeshSnapshot?> Read(CancellationToken token)=>Task.FromResult<MeshSnapshot?>(new(mesh.Directory!,[]));
        public void Dispose(){}
    }
}
