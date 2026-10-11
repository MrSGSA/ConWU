using StreamLink.Core;

namespace StreamLink.Service;

// At most one proven path and one tentative replacement per member. The
// replacement must pass the router's authenticated round trip before retirement.
internal sealed class MeshPeerTransports(MeshRouter router, Func<string, IMeshTransport> create, Action<string> log) : IDisposable
{
    (string Endpoint, IMeshTransport Transport)? active, pending;
    long started, nextAttempt;
    int failures;
    string requested = "";
    public bool HasPending => pending != null;
    public void Update(int slot, string endpoint, string name, string detail, Func<bool>? beginAttempt = null, bool keepPending = true)
    {
        long now = Environment.TickCount64;
        if (endpoint.Length > 0 && endpoint != requested) { requested = endpoint; failures = 0; nextAttempt = 0; }
        if (active?.Transport.Exited == true) { Close(active); active = null; }
        if (pending != null && router.UsesPath(slot, pending.Value.Transport.ClientEndpoint) && !pending.Value.Transport.Exited) {
            Close(active); active = pending; pending = null; failures = 0; nextAttempt = 0;
            log($"设备 {slot} 已通过双向验证，使用新的直连路径");
        }
        if (!keepPending && pending != null) { Close(pending); pending = null; }
        if (pending != null && (pending.Value.Transport.Exited || now - started >= 15000)) {
            Close(pending); pending = null; Retry(now);
            log($"设备 {slot} 新路径暂不可用，保留已有路径");
        }
        if (pending != null && endpoint.Length > 0 && endpoint != pending.Value.Endpoint) { Close(pending); pending = null; nextAttempt = 0; }
        if (pending == null && endpoint.Length > 0 && endpoint != active?.Endpoint && now >= nextAttempt && (beginAttempt?.Invoke() ?? true)) {
            try { pending = (endpoint, create(endpoint)); started = now; }
            catch (Exception ex) { Retry(now); log($"设备 {slot} 传输重试：{ex.Message}"); }
        }
        router.SetCandidate(slot, pending?.Transport.ClientEndpoint ?? active?.Transport.ClientEndpoint, name, detail);
    }
    void Retry(long now) { failures = Math.Min(failures + 1, 4); nextAttempt = now + Math.Min(15000, 1000 << failures); }
    static void Close((string Endpoint, IMeshTransport Transport)? path) => path?.Transport.Dispose();
    public void Dispose() { try { Close(pending); } finally { Close(active); pending = active = null; } }
}
