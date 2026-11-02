using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace StreamLink.Core;

public sealed record TcpBindingSnapshot(Guid LeaseId, Guid Generation, string Local, string Reflector, string Server, bool QueryUsable, bool Closed);

// Keep the actual STUN TCP flow alive; do not depend on an unrelated HTTP host.
public sealed class TcpBinding : IDisposable
{
    readonly TcpEndpointLease lease;
    readonly string server;
    int disposed;
    static int fallbackOffset;
    TcpBinding(TcpEndpointLease lease, string server) { this.lease = lease; this.server = server; }
    public TcpBindingSnapshot Snapshot => new(lease.Id, lease.NetworkGeneration, lease.Local.ToString(), lease.Reflector.ToString(), server, lease.QueryUsable, lease.Closed);
    public static Task<(TcpBinding Binding, StunResult Result)> Connect(int port, IPAddress? local, Action<string> log, CancellationToken token, IEnumerable<string>? servers = null)
    {
        if(port is <1 or >65535)throw new ArgumentOutOfRangeException(nameof(port));
        return ConnectCore(port, local, log, token, servers,
            (server, ct) => Stun.Query(true, server, 0, ct, local, TcpHelperPurpose.ServerScreening));
    }
    // Only for a NEW mapping. Existing mappings retain their exact source tuple
    // for the entire lease; changing that tuple also requires a new router lease.
    public static async Task<(TcpBinding Binding, StunResult Result)> ConnectAvailable(int preferredPort,int receiverPort,
        IPAddress? local,Action<string> log,CancellationToken token,IEnumerable<string>? servers=null)
    {
        try{return await Connect(preferredPort,local,log,token,servers);}
        catch(TcpEndpointBusyException){log($"内部 TCP STUN 源端口 {preferredPort} 被占用，正在分配可用源端口；接收端口 {receiverPort} 保持不变");}
        for(int attempt=0;attempt<3;attempt++){
            var result=await ConnectCore(0,local,log,token,servers,(server,ct)=>Stun.Query(true,server,0,ct,local,TcpHelperPurpose.ServerScreening));
            if(result.Result.Local.Port!=receiverPort){log($"内部 TCP STUN 已分配源端口 {result.Result.Local.Port}，将公告真实映射端点");return result;}
            result.Binding.Dispose();
        }
        throw new IOException("未能分配与接收端口不同的 TCP STUN 源端口，请稍后重试");
    }
    internal static async Task<(TcpBinding Binding, StunResult Result)> ConnectCore(int port, IPAddress? local, Action<string> log,
        CancellationToken token, IEnumerable<string>? servers, Func<string, CancellationToken, Task> screen)
    {
        if (port is < 0 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        string[] choices = (servers ?? Stun.TcpServers).Distinct(StringComparer.OrdinalIgnoreCase).Take(256).ToArray();
        if (choices.Length == 0) throw new IOException("TCP STUN 列表为空");
        using var round = CancellationTokenSource.CreateLinkedTokenSource(token); round.CancelAfter(TimeSpan.FromSeconds(12));
        using var preferredStop = CancellationTokenSource.CreateLinkedTokenSource(round.Token);
        // Only ONE socket ever uses the actual source port. Other sockets screen
        // server health on ephemeral ports; their observed endpoints are discarded.
        var preferred = Open(choices[0], port, local, preferredStop.Token);
        var ready = Channel.CreateBounded<string>(new BoundedChannelOptions(3) { FullMode = BoundedChannelFullMode.Wait });
        string[] tail = choices.Skip(1).ToArray();
        // Rotate the tail between rounds so a long list with a dead prefix does
        // not permanently starve later servers. The remembered first choice stays first.
        int offset = tail.Length == 0 ? 0 : (int)((uint)(Interlocked.Add(ref fallbackOffset, 12) - 12) % (uint)tail.Length);
        tail = tail.Skip(offset).Concat(tail.Take(offset)).ToArray();
        int next = -1;
        async Task Screen()
        {
            await Task.Delay(350, round.Token);
            while (Interlocked.Increment(ref next) is int index && index < tail.Length) {
                string candidate = tail[index];
                try {
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(round.Token); timeout.CancelAfter(2000);
                    await screen(candidate, timeout.Token);
                    await ready.Writer.WriteAsync(candidate, round.Token);
                } catch (Exception ex) when (!round.IsCancellationRequested && ex is SocketException or IOException or OperationCanceledException or ArgumentException) { }
                await Task.Delay(150, round.Token);
            }
        }
        async Task ScreenAll()
        {
            try { await Task.WhenAll(Enumerable.Range(0, Math.Min(3, tail.Length)).Select(_ => Screen())); }
            finally { ready.Writer.TryComplete(); }
        }
        Task screening = ScreenAll(); TcpBinding? winner = null;
        try {
            Task<bool> available = ready.Reader.WaitToReadAsync(round.Token).AsTask();
            await Task.WhenAny(preferred, available);
            if (preferred.IsCompleted) {
                try { var first = await preferred; winner = first.Binding; return first; }
                catch (Exception ex) when (!round.IsCancellationRequested && ex is not TcpEndpointBusyException) { log("TCP STUN 首选服务失败：" + Failure(ex)); }
            } else if (await available) {
                preferredStop.Cancel();
                try { var first = await preferred; winner = first.Binding; return first; }
                catch (Exception ex) when (!round.IsCancellationRequested && ex is not TcpEndpointBusyException) { log("TCP STUN 切换到已通过检查的备用服务"); }
            } else {
                var first = await preferred; winner = first.Binding; return first;
            }
            // The preferred socket has been fully closed before rebinding.
            while (await ready.Reader.WaitToReadAsync(round.Token)) {
                while (ready.Reader.TryRead(out string? candidate)) {
                    try { var result = await Open(candidate, port, local, round.Token); winner = result.Binding; return result; }
                    catch (Exception ex) when (!round.IsCancellationRequested && ex is not TcpEndpointBusyException) { log("TCP STUN 固定端口复核失败：" + Failure(ex)); }
                }
            }
            throw new IOException("没有可用的 TCP STUN 服务");
        } catch (OperationCanceledException) when (!token.IsCancellationRequested) {
            throw new IOException("TCP STUN 本轮 12 秒预算已用尽，将在后台重试");
        } finally {
            try {
                round.Cancel(); preferredStop.Cancel();
                try { var first = await preferred; if (!ReferenceEquals(first.Binding, winner)) first.Binding.Dispose(); } catch { }
                try { await screening; }
                // Cancelled DNS/Connect may complete with a Winsock error on
                // Windows. Losing screens cannot replace the successful result.
                catch (Exception ex) when (ex is OperationCanceledException or SocketException or IOException or ArgumentException) { }
                token.ThrowIfCancellationRequested();
            } catch {
                // The caller never receives a return value when finally fails.
                // Retain no unowned winner, even on an unexpected cleanup fault.
                winner?.Dispose(); throw;
            }
        }
    }
    static string Failure(Exception ex) => ex is OperationCanceledException ? "超时" : ex is SocketException socket ? socket.SocketErrorCode.ToString() : ex.Message;
    static async Task<(TcpBinding Binding, StunResult Result)> Open(string server, int port, IPAddress? local, CancellationToken token)
    {
        TcpEndpointLease? lease = null;
        TcpBinding? connection = null;
        try {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(4000);
            var endpoint = await Stun.Resolve(server, timeout.Token);
            lease = await TcpEndpointLease.Open(new(local ?? Stun.LocalAddress(endpoint), port), endpoint, Guid.NewGuid(), timeout.Token, TcpHelperPurpose.LegacyEntry);
            connection = new TcpBinding(lease, server);
            return (connection, await connection.Pulse(timeout.Token));
        } catch { connection?.Dispose(); lease?.Dispose(); throw; }
    }
    public async Task<StunResult> Pulse(CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (!lease.QueryUsable) throw new IOException("STUN 辅助资源在失败事务后不可再查询");
        using var reference = lease.AcquireAttempt(lease.NetworkGeneration);
        return (await reference.Observe(token)) with { Server = server };
    }
    public void Dispose() { if (Interlocked.Exchange(ref disposed, 1) == 0) lease.Dispose(); }
}
