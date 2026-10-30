using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task PumpFaultRecovery(string? output=null)
    {
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");var guest=Guest(owner);guest.Directory=owner.Directory;
        byte[] key=MeshIdentity.SharedKey(guest,owner.Self);using var link=new MeshLink(2,1,key);CryptographicOperations.ZeroMemory(key);
        await using var peer=new PeerEndpoint(link);var adapter=new MemoryAdapter();
        var discovery=new Discovery(owner,guest,peer.Endpoint.ToString());var transports=new List<ForwardingTransport>();
        SessionStatus? status=null;bool lossPublishedBeforeCleanup=false;
        string root=Path.Combine(Path.GetTempPath(),"StreamLink-pump-fault-"+Guid.NewGuid().ToString("N"));
        var services=new MeshRuntimeServices(_=>discovery,_=>Task.FromResult<IPacketAdapter>(adapter),
            async(_,_,ct)=>{await Task.Delay(Timeout.Infinite,ct);throw new IOException();},
            r=>{var t=new ForwardingTransport(r.Target);transports.Add(t);return t;},
            (_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},root) {
                Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(null)
            };
        var runner=new MeshRunner(new DeviceProfile{Mesh=owner},Console.WriteLine,s=>{
            status=s;if(s.Connection?.Phase=="Recovering"&&!s.Connected&&!adapter.Disposed)lossPublishedBeforeCleanup=true;
        },_=>{},_=>{},services);
        using var stop=new CancellationTokenSource();var running=runner.Run(stop.Token);
        try {
            await Until(()=>status?.Connected==true,"pump fault fixture has a healthy production Runner");
            adapter.ReadFault=true;Exception? failure=null;
            try{await running.WaitAsync(TimeSpan.FromSeconds(8));}catch(IOException ex){failure=ex;}
            Check(lossPublishedBeforeCleanup&&status?.Connected==false,"pump failure clears connected status before owner cleanup");
            Check(failure is IOException and not MeshShutdownException && runner.CleanupComplete && runner.UnprovenOwnerCount==0,
                "a joined pump fault with successful owner cleanup remains retryable, not an unproven-shutdown error");
            Check(adapter.Disposed&&discovery.Disposed&&transports.All(t=>t.Disposed),"fault cleanup releases adapter, discovery and every client");
            if(output!=null){Directory.CreateDirectory(Path.GetDirectoryName(output)!);await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{
                status="Pass",failure=failure!.Message,runner.CleanupComplete,runner.UnprovenOwnerCount,lossPublishedBeforeCleanup,
                scope="production Runner and Router with real encrypted UDP loopback; injected adapter read exception; actual Windows driver fault not covered"
            },new JsonSerializerOptions{WriteIndented=true}));}
        } finally {stop.Cancel();try{await running;}catch(IOException){}catch(OperationCanceledException){}}
    }
}
