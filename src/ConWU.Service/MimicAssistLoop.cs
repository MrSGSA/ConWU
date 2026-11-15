using System.Diagnostics;
using StreamLink.Core;

namespace StreamLink.Service;

// One cancellable control cycle per autonomous network. At most 15 steady
// hint requests/minute leave room for watch/publish in the 48/min member cap. Preparation and HTTP
// never run under the router lock; healthy business paths stop hint polling.
internal sealed class TcpAssistLoop(MeshProfile mesh,ITcpAssistDiscovery discovery,Action<string> log,CancellationToken token):IAsyncDisposable
{
    readonly CancellationTokenSource stop=CancellationTokenSource.CreateLinkedTokenSource(token);
    CancellationTokenSource? cycleStop;
    Task? cycle;
    IMeshTransport? receiver;
    string current="";
    long next,warningAt;
    bool unavailable;
    void Warn(Exception error)
    {if(Environment.TickCount64-warningAt>=30000||warningAt==0){warningAt=Environment.TickCount64;log("协调辅助暂未建立 "+TransportModes.Label(mesh.Pair.Mode)+" 通道："+error.GetType().Name+"；已有直连保持运行");}}
    async Task Finish()
    {
        if(cycle==null)return;cycleStop!.Cancel();
        try{await cycle;}
        catch(NotSupportedException){unavailable=true;}
        catch(Exception error)when(error is IOException or HttpRequestException or OperationCanceledException or ArgumentException or FormatException){if(error is not OperationCanceledException&&!stop.IsCancellationRequested)Warn(error);}
        finally{cycle=null;cycleStop.Dispose();cycleStop=null;next=Environment.TickCount64+4000;}
    }
    public async Task Tick(IMapping? mapping,IMeshTransport? transport,MeshRouter? router)
    {
        var peer=mesh.Directory?.Members.SingleOrDefault(m=>m.Slot!=mesh.Self.Slot);
        string candidate=mapping is {IsValid:true}?mapping.PublicEndpoint.ToString():"";
        bool needed=!unavailable&&peer!=null&&router!=null&&!router.HasHealthyPath(peer.Slot)&&transport is IMeshPunchTransport&&!transport.Exited&&candidate.Length>0;
        bool changed=candidate!=current||!ReferenceEquals(receiver,transport);
        if(changed||!needed||cycle?.IsCompleted==true)await Finish();
        current=candidate;receiver=transport;
        if(!needed||cycle!=null||Environment.TickCount64<next||stop.IsCancellationRequested)return;
        cycleStop=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
        cycle=Run(candidate,(IMeshPunchTransport)transport!,router!,peer!.Slot,cycleStop.Token);
    }
    async Task Run(string candidate,IMeshPunchTransport transport,MeshRouter router,int slot,CancellationToken token)
    {
        string prepared="";Guid lastRound=Guid.Empty;
        while(true){
            token.ThrowIfCancellationRequested();if(router.HasHealthyPath(slot))return;
            long began=Stopwatch.GetTimestamp();
            var state=await discovery.AssistTcp(candidate,mesh.Pair.Mode,prepared.Length>0,token);
            if(state.Mode!=mesh.Pair.Mode)throw new IOException("协调辅助返回了其他传输协议");
            if(state.PeerEndpoint.Length>0&&state.PeerEndpoint!=prepared){
                // Retract readiness before preparing a changed peer. A previous
                // round may never start with a new candidate or receiver.
                if(prepared.Length>0)await discovery.AssistTcp(candidate,mesh.Pair.Mode,false,token);
                await transport.PreparePunch(PunchAssistProtocol.Candidate(state.PeerEndpoint),!mesh.IsOwner,token);
                prepared=state.PeerEndpoint;continue;
            }
            if(state.Round!=Guid.Empty&&state.Round!=lastRound&&prepared.Length>0&&state.StartAfterMilliseconds>=-1000){
                int delay=Math.Max(0,state.StartAfterMilliseconds-(int)(Stopwatch.GetElapsedTime(began).TotalMilliseconds/2));
                if(delay>0)await Task.Delay(delay,token);
                token.ThrowIfCancellationRequested();if(router.HasHealthyPath(slot))return;
                await transport.StartPunch(PunchAssistProtocol.Candidate(prepared),router.AssistanceGreeting(slot),token);
                lastRound=state.Round;
                log("协调辅助已启动 "+TransportModes.Label(mesh.Pair.Mode)+" 同源端口双向探测；等待加密握手与往返验证");
            }
            await Task.Delay(4000,token);
        }
    }
    public async ValueTask DisposeAsync(){stop.Cancel();try{await Finish();}finally{stop.Dispose();}}
}
