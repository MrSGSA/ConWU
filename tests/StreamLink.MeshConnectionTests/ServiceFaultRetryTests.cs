using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task ServiceFaultRetry(string? output=null)
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");var guest=Guest(owner);guest.Directory=owner.Directory;
        byte[] key=MeshIdentity.SharedKey(guest,owner.Self);using var link=new MeshLink(2,1,key);CryptographicOperations.ZeroMemory(key);
        await using var peer=new PeerEndpoint(link);var adapters=new ConcurrentQueue<MemoryAdapter>();
        var store=new ProfileStore();store.Save(new DeviceProfile{Mesh=owner,Enabled=true});
        string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        bool overlap=false;
        var services=new MeshRuntimeServices(_=>new Discovery(owner,guest,peer.Endpoint.ToString()),
            _=>{if(adapters.Any(a=>!a.Disposed))overlap=true;var adapter=new MemoryAdapter();adapters.Enqueue(adapter);return Task.FromResult<IPacketAdapter>(adapter);},
            async(_,_,ct)=>{await Task.Delay(Timeout.Infinite,ct);throw new IOException();},
            r=>new ForwardingTransport(r.Target),(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},Path.Combine(ProfileStore.Root,"sessions")) {
                Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(null)
            };
        using var worker=new ControlWorker(services);worker.StartLocal();
        UiStatusDto? status=null;
        async Task<UiStatusDto?> Read(){status=(await worker.HandleUi(new("status"),sid,CancellationToken.None)).Status;return status;}
        async Task Wait(Func<UiStatusDto?,bool> condition,int timeout=8000){
            var clock=System.Diagnostics.Stopwatch.StartNew();while(!condition(await Read())){if(clock.ElapsedMilliseconds>timeout)throw new Exception("Service status timeout");await Task.Delay(50);}
        }
        try {
            await Wait(s=>s?.DirectPeers==1);var original=adapters.Single();original.ReadFault=true;
            await Wait(s=>s?.Connection?.Phase=="Retrying");
            Check(status is {DirectPeers:0,Connection.RetryInSeconds:>0}&&original.Disposed,
                "actual ControlWorker publishes disconnected retry countdown after a data-pump fault");
            var denied=await worker.HandleUi(new("retry",OperationId:Guid.NewGuid()),"S-1-5-21-111-222-333-444",CancellationToken.None);
            Check(!denied.Ok&&adapters.Count==1,"unauthorized retry cannot restart any owner");
            var retry=await worker.HandleUi(new("retry",OperationId:Guid.NewGuid()),sid,CancellationToken.None);
            Check(retry.Ok,"authorized restricted retry accepted during backend backoff");
            await Wait(s=>s?.DirectPeers==1&&adapters.Count==2,4000);
            Check(!overlap&&original.Disposed&&adapters.Count==2,"real background loop reconnects after proven cleanup without overlapping adapters");
            var duplicate=await worker.HandleUi(new("retry",OperationId:Guid.NewGuid()),sid,CancellationToken.None);
            Check(!duplicate.Ok&&adapters.Count==2,"repeated retry requests respect the backend ten second limit");
            if(output!=null){Directory.CreateDirectory(Path.GetDirectoryName(output)!);await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{
                status="Pass",adapters=adapters.Count,overlap,scope="real isolated ControlWorker/restricted API/restart loop with injected adapter read fault and encrypted UDP loopback; no installed SCM service or physical network"
            },new JsonSerializerOptions{WriteIndented=true}));}
        } finally {await worker.StopLocal();}
    }
}
