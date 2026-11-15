using System.Net;
using System.Net.Sockets;
using StreamLink.Core;

static class EntryProbeTests
{
    public static async Task Run(Action<bool,string> check)
    {
        var reports=new List<EntryProbeProgress>();var logs=new List<string>();
        try{
            await HostEntryProbe.Run((progress,_)=>{
                progress(new("StunQuery","正在查询 TCP STUN"));
                throw new SocketException((int)SocketError.NetworkUnreachable);
            },logs.Add,reports.Add,CancellationToken.None,TimeSpan.FromSeconds(2));
            throw new Exception("failed probe returned an entry");
        }catch(EntryProbeException error){
            check(error.Stage=="StunQuery"&&error.Reason=="NetworkUnreachable"&&error.InnerException is SocketException,
                "failed STUN reports its stage and socket reason without inventing an entry");
            check(reports.Select(r=>r.Stage).SequenceEqual(new[]{"Starting","StunQuery"})&&logs.Any(s=>s.Contains("stage=StunQuery")&&s.Contains("elapsedMs=")),
                "entry progress and structured timing reach the observer");
        }
        bool exited=false;
        try{
            await HostEntryProbe.Run(async (progress,token)=>{
                progress(new("PortControl","正在请求本地网关映射"));
                try{await Task.Delay(Timeout.Infinite,token);}finally{exited=true;}
                throw new Exception("unreachable");
            },_=>{},_=>{},CancellationToken.None,TimeSpan.FromMilliseconds(80));
            throw new Exception("unbounded probe unexpectedly returned");
        }catch(EntryProbeException error){
            check(error.Stage=="PortControl"&&error.Reason=="Timeout"&&exited,"probe budget cancels and joins the gateway attempt before reporting failure");
        }
        using(var canceled=new CancellationTokenSource()){
            canceled.Cancel();bool invoked=false;
            try{
                await HostEntryProbe.Run((_,_)=>{invoked=true;throw new Exception("must not start");},_=>{},_=>{},canceled.Token,TimeSpan.FromSeconds(1));
                throw new Exception("canceled probe unexpectedly returned");
            }catch(OperationCanceledException){
                check(!invoked,"caller cancellation remains cancellation and opens no resource");
            }
        }
        var late=new Mapping();
        try{
            await HostEntryProbe.Run(async (_,_)=>{await Task.Delay(100);return late;},_=>{},_=>{},CancellationToken.None,TimeSpan.FromMilliseconds(20));
            throw new Exception("late result was published");
        }catch(EntryProbeException error){check(error.Reason=="Timeout"&&late.Disposed,"a provider returning after its budget cannot publish or leak its late mapping");}
        var valid=new Mapping();
        var result=await HostEntryProbe.Run((progress,_)=>{progress(new("GatewayMapping","正在申请独立映射"));return Task.FromResult<IMapping>(valid);},_=>{},_=>{},CancellationToken.None,TimeSpan.FromSeconds(1));
        check(ReferenceEquals(result,valid)&&!valid.Disposed,"successful mapping ownership transfers to the caller");
        await result.DisposeAsync();
        bool fallback=false;
        try{
            await GatewayMapping.SelectTcp(_=>Task.FromException<TcpMapping>(new IOException("fixture: UPnP not available")),()=>[],
                (_,_)=>throw new Exception("no gateway should be opened"),true,_=>{},CancellationToken.None,()=>fallback=true);
            throw new Exception("unavailable gateway unexpectedly returned");
        }catch(IOException error){
            check(fallback&&error.Message.Contains("UPnP not available")&&error.Message.Contains("PCP")&&error.InnerException is AggregateException,
                "gateway fallback retains the first failure and identifies its own failed stage");
        }
    }
    sealed class Mapping:IMapping
    {
        public bool Disposed;
        public bool IsValid=>!Disposed;
        public IPAddress LocalAddress=>IPAddress.Loopback;
        public IPEndPoint PublicEndpoint=>new(IPAddress.Parse("203.0.113.18"),48000);
        public event Action<IPEndPoint>? Changed {add{}remove{}}
        public Task Maintain(CancellationToken token)=>Task.Delay(Timeout.Infinite,token);
        public ValueTask DisposeAsync(){Disposed=true;return ValueTask.CompletedTask;}
    }
}
