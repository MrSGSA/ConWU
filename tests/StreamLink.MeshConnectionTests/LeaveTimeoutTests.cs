using System.Reflection;
using System.Security.Principal;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    sealed class ClosingPairClient(bool wait):IShortPairClient
    {
        public bool Disposed;public int Closed;
        public async Task Close(PairRoomTicket room,CancellationToken token){Closed++;if(wait)await Task.Delay(Timeout.Infinite,token);throw new OperationCanceledException("synthetic pairing-close transport deadline");}
        public void Dispose()=>Disposed=true;
        public Task<PairRoomTicket> Create(PairKeyExchange key,string name,CancellationToken token)=>throw new NotSupportedException();
        public Task<PairRoomTicket> Join(string code,PairKeyExchange key,string name,CancellationToken token,string requestedIp="",MeshRejoinProof? rejoin=null)=>throw new NotSupportedException();
        public Task<PairRoomState> Poll(PairRoomTicket room,bool owner,CancellationToken token)=>throw new NotSupportedException();
        public Task<PairRoomState> Reveal(PairRoomTicket room,bool owner,PairKeyExchange key,CancellationToken token)=>throw new NotSupportedException();
        public Task<PairRoomState> Approve(PairRoomTicket room,string candidate,string cipher,CancellationToken token)=>throw new NotSupportedException();
        public Task<PairRoomState> Finish(PairRoomTicket room,bool owner,CancellationToken token)=>throw new NotSupportedException();
    }
    static async Task LeaveTimeouts()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var store=new ProfileStore();var sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        foreach(bool wait in new[]{false,true}){
            var owner=MeshIdentity.Create("https://example.com/","","faketcp");store.Save(new DeviceProfile{Mesh=owner,Enabled=false});
            using var worker=new ControlWorker();var closing=new ClosingPairClient(wait);
            void Set(string field,object value)=>typeof(ControlWorker).GetField(field,BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(worker,value);
            Set("uiPairClient",closing);Set("uiPairOwner",true);Set("uiRoom",new PairRoomTicket("fixture-room","123456","fixture-token","fixture-commit","fixture",DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeSeconds()));
            var reply=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("delete-network",ExpectedNetwork:owner.Pair.Network,ConfirmReplace:true)),sid,default);
            Check(reply.Ok,"deleting a single-member network does not fail on optional pairing-room close timeout");
            await Until(()=>store.Load().Mesh==null,"network deletion commits after bounded optional pairing cleanup",6500);
            Check(closing.Closed==1&&closing.Disposed&&!store.Load().Enabled,"leave closes pairing resources exactly once and persists the disabled empty network");
        }
        var retained=MeshIdentity.Create("https://example.com/","","faketcp");store.Save(new DeviceProfile{Mesh=retained,Enabled=false});
        using(var worker=new ControlWorker()){
            var closing=new ClosingPairClient(true);
            foreach(var pair in new Dictionary<string,object>{{"uiPairClient",closing},{"uiPairOwner",true},{"uiRoom",new PairRoomTicket("cancel-room","123456","fixture-token","fixture-commit","fixture",DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeSeconds())}})
                typeof(ControlWorker).GetField(pair.Key,BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(worker,pair.Value);
            using var cancelled=new CancellationTokenSource();cancelled.Cancel();bool propagated=false;
            try{await (Task)typeof(ControlWorker).GetMethod("CloseUiPair",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(worker,[cancelled.Token])!;}catch(OperationCanceledException){propagated=true;}
            Check(propagated&&closing.Disposed&&store.Load().Mesh?.Pair.Network==retained.Pair.Network,"caller cancellation remains cancellation and cannot silently delete the network");
        }
        await LeaveRevocation(store,sid);
        Console.WriteLine($"PASS {checks} pairing-close/leave timeout checks");
    }
    static async Task LeaveRevocation(ProfileStore store,string sid)
    {
        using var signing=RSA.Create(2048);var certificateRequest=new CertificateRequest("CN=localhost",signing,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        using var generated=certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
        using var certificate=X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx),null);
        var builder=WebApplication.CreateSlimBuilder();builder.Logging.ClearProviders();builder.WebHost.ConfigureKestrel(o=>o.Listen(IPAddress.Loopback,0,l=>l.UseHttps(certificate)));
        await using var app=builder.Build();int calls=0;string mode="";MeshDirectory? applied=null;
        app.MapPut("/v3/mesh/{network}/directory",async(MeshDirectory directory,HttpContext context)=>{
            calls++;if(mode=="forbidden")return Results.StatusCode(403);
            if(applied!=null&&applied.Signature!=directory.Signature)throw new Exception("retry changed the revocation table");
            applied=directory;
            if(calls==1){if(mode=="timeout")await Task.Delay(Timeout.Infinite,context.RequestAborted);else return Results.StatusCode(503);}
            return Results.NoContent();
        });
        await app.StartAsync();string url=app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single()+"/";
        string pin=Convert.ToHexString(SHA256.HashData(certificate.RawData));
        try{foreach(string scenario in new[]{"transient","timeout","forbidden"}){
            mode=scenario;calls=0;applied=null;var owner=MeshIdentity.Create(url,pin,"faketcp");MeshIdentity.Issue(owner);store.Save(new DeviceProfile{Mesh=owner,Enabled=false});
            using var worker=new ControlWorker();
            var reply=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("delete-network",ExpectedNetwork:owner.Pair.Network,ConfirmReplace:true)),sid,default);
            if(scenario=="forbidden")Check(!reply.Ok&&calls==1&&store.Load().Mesh?.Directory?.Members.Length==2,"required member revocation rejection preserves network and is never treated as optional cleanup");
            else Check(reply.Ok&&calls==2&&applied?.Members.Length==1&&store.Load().Mesh==null,"lost revocation acknowledgement retries the identical signed table and completes deletion: "+scenario);
        }}finally{await app.StopAsync();}
    }
}
