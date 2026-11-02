using StreamLink.Core;

namespace StreamLink.Service;

// At most one proven path and one tentative replacement per member. The
// replacement must pass the router's authenticated round trip before retirement.
internal sealed class MeshPeerTransports : IDisposable, IAsyncDisposable
{
    readonly MeshRouter router;
    readonly Func<string, CancellationToken, Task<IMeshTransport>> create;
    readonly Action<string> log;
    public MeshPeerTransports(MeshRouter router, Func<string, IMeshTransport> create, Action<string> log)
        : this(router, (endpoint, _) => Task.FromResult(create(endpoint)), log) { }
    public MeshPeerTransports(MeshRouter router, Func<string, CancellationToken, Task<IMeshTransport>> create, Action<string> log)
    { this.router = router; this.create = create; this.log = log; }
    (string Endpoint, IMeshTransport Transport)? active, pending;
    Task<IMeshTransport>? preparing;
    CancellationTokenSource? preparationStop;
    string preparationEndpoint = "";
    bool disposed;
    long started, nextAttempt;
    long preparationBegan;
    int failures;
    int attempts;
    string requested = "";
    public bool HasPending => pending != null || preparing != null;
    public ConnectionProgress Progress(long now) => nextAttempt > now
        ? new("Retrying","上次直连验证未通过，后台将重新尝试。",Attempt:attempts,RetryInSeconds:(int)((nextAttempt-now+999)/1000),CanRetry:true)
        : new(preparing != null ? "Preparing" : pending != null ? "Verifying" : "Connecting",
            preparing != null ? "正在准备直连传输" : pending != null ? "正在验证直连往返" : "正在寻找可用直连入口",
            Attempt:attempts,RemainingSeconds:HasPending?(int)Math.Max(0,(preparationBegan+15000-now+999)/1000):null,CanRetry:true);
    public void WakeRetry() { nextAttempt = 0; failures = 0; }
    public void Suspend(int slot,string name)
    {
        Update(slot,"",name,"设备未在线，等待上线后再连接",keepPending:false);
        if(active!=null&&!router.HasHealthyPath(slot)){
            router.FailLegacyTransport(slot,active.Value.Transport.ClientEndpoint);Close(active);active=null;
            router.SetCandidate(slot,null,name,"设备未在线，等待上线后再连接");
        }
    }
    public void InvalidatePreparation(int slot)
    {
        preparationStop?.Cancel();
        // A pending transport may already be the authenticated carrying path
        // before the next manager tick. Preserve it as Active before clearing.
        if(pending is{}candidate&&router.UsesPath(slot,candidate.Transport.ClientEndpoint)&&!candidate.Transport.Exited){Close(active);active=pending;pending=null;}
        if(pending!=null){router.CancelLegacyCandidate(slot,pending.Value.Transport.ClientEndpoint);Close(pending);pending=null;}
        WakeRetry();
    }
    public void Update(int slot, string endpoint, string name, string detail, Func<bool>? beginAttempt = null, bool keepPending = true)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        long now = Environment.TickCount64;
        if (endpoint.Length > 0 && endpoint != requested) { requested = endpoint; failures = 0; nextAttempt = 0; }
        if (preparing != null) {
            if (!keepPending || endpoint != preparationEndpoint) preparationStop!.Cancel();
            if (preparing.IsCompleted) {
                try {
                    var prepared = preparing.GetAwaiter().GetResult();
                    if (preparationStop!.IsCancellationRequested) prepared.Dispose();
                    else {
                        pending = (preparationEndpoint, prepared); started = preparationBegan;
                        log($"设备 {slot} 传输准备完成，排队与启动耗时 {now - preparationBegan} ms");
                    }
                } catch (OperationCanceledException) when (preparationStop!.IsCancellationRequested) { }
                catch (Exception ex) { Retry(now); log($"设备 {slot} 传输重试：{ex.Message}"); }
                finally { preparing = null; preparationStop!.Dispose(); preparationStop = null; }
            }
        }
        if (active?.Transport.Exited == true) {
            log($"设备 {slot} 传输进程失效：{active.Value.Transport.FailureReason}；立即撤销该路径，重新验证连接");
            router.FailLegacyTransport(slot,active.Value.Transport.ClientEndpoint);Close(active);active=null;
        }
        if (pending != null && router.UsesPath(slot, pending.Value.Transport.ClientEndpoint) && !pending.Value.Transport.Exited) {
            Close(active); active = pending; pending = null; failures = 0; nextAttempt = 0;
            log($"设备 {slot} 已通过双向验证，实际直连入口 {active.Value.Endpoint}");
        }
        if ((!keepPending || endpoint.Length == 0) && pending != null) { router.CancelLegacyCandidate(slot, pending.Value.Transport.ClientEndpoint); Close(pending); pending = null; }
        if (pending != null && (pending.Value.Transport.Exited || now - started >= 15000)) {
            if(pending.Value.Transport.Exited){
                log($"设备 {slot} 候选传输失效：{pending.Value.Transport.FailureReason}");
                router.FailLegacyTransport(slot,pending.Value.Transport.ClientEndpoint);
            }
            router.CancelLegacyCandidate(slot, pending.Value.Transport.ClientEndpoint); Close(pending); pending = null; Retry(now);
            log($"设备 {slot} 新路径暂不可用，保留已有路径");
        }
        if (pending != null && endpoint.Length > 0 && endpoint != pending.Value.Endpoint) { router.CancelLegacyCandidate(slot, pending.Value.Transport.ClientEndpoint); Close(pending); pending = null; nextAttempt = 0; }
        // A live native process can have a dead wire path (NAT state cleared,
        // sleep or source-route change). An unchanged authenticated announcement
        // is still eligible for a NEW independently bound client. Do not stop
        // the retained transport merely because its health window elapsed.
        bool replaceDisconnected = active != null && !router.HasHealthyPath(slot);
        if (preparing == null && pending == null && keepPending && endpoint.Length > 0 && (endpoint != active?.Endpoint || replaceDisconnected) && now >= nextAttempt && (beginAttempt?.Invoke() ?? true)) {
            try {
                attempts++; preparationEndpoint = endpoint; preparationBegan = now; preparationStop = new(); preparationStop.CancelAfter(15000);
                preparing = create(endpoint, preparationStop.Token);
                if (preparing.IsCompletedSuccessfully) {
                    pending = (endpoint, preparing.Result); started = now; preparing = null;
                    preparationStop.Dispose(); preparationStop = null;
                }
            }
            catch (Exception ex) { preparationStop?.Dispose(); preparationStop = null; preparing = null; Retry(now); log($"设备 {slot} 传输重试：{ex.Message}"); }
        }
        var transport = pending?.Transport ?? active?.Transport;
        router.SetCandidate(slot, transport?.ClientEndpoint, name, detail, transport?.ControlsWirePackets == true);
    }
    void Retry(long now) { failures = Math.Min(failures + 1, 4); nextAttempt = now + Math.Min(15000, 1000 << failures); }
    static void Close((string Endpoint, IMeshTransport Transport)? path) => path?.Transport.Dispose();
    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    public async ValueTask DisposeAsync()
    {
        if (disposed) return; disposed = true; preparationStop?.Cancel();
        try {
            if (preparing != null) {
                try { (await preparing).Dispose(); }
                catch (OperationCanceledException) when (preparationStop!.IsCancellationRequested) { }
            }
        } finally {
            preparing = null; preparationStop?.Dispose(); preparationStop = null;
            try { Close(pending); } finally { Close(active); pending = active = null; }
        }
    }
}
