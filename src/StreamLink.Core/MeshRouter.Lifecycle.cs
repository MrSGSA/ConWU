namespace StreamLink.Core;

public sealed partial class MeshRouter
{
    readonly TaskCompletionSource closeCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public ValueTask DisposeAsync()
    {
        // Publish one completion before invoking cancellation callbacks. A
        // concurrent/repeated close must observe the same join and failure,
        // never treat "close started" as permission to reuse the adapter.
        if (Interlocked.CompareExchange(ref disposed, 1, 0) == 0) _ = CompleteClose();
        return new(closeCompletion.Task);
    }

    async Task CompleteClose()
    {
        try { await CloseResources(); closeCompletion.TrySetResult(); }
        catch (Exception ex) { closeCompletion.TrySetException(ex); }
    }

    async Task CloseResources()
    {
        List<Exception> failures = [];
        void Cleanup(string stage, Action action)
        {
            try { action(); }
            catch (Exception ex) { failures.Add(new IOException("路由器回收失败：" + stage, ex)); }
        }

        Cleanup("cancel", stop.Cancel);
        Cleanup("adapter-stop", adapter.Stop);
        Task[] pathPumps;
        lock (gate) {
            foreach (var peer in peers.Values) Cleanup("path-cancel", () => CloseManaged(peer));
            pathPumps = managedPumps.ToArray();
        }

        // Joining an operationally failed pump still proves it has stopped.
        // Resource-close errors are different and remain terminal below.
        try { await Task.WhenAll(transmit, receive, heartbeat, Completion); } catch (Exception) { }
        var pathsClosed = Task.WhenAll(pathPumps);
        try { await pathsClosed; }
        catch (Exception ex) { failures.Add(new IOException("路由器回收失败：path-release", pathsClosed.Exception ?? ex)); }

        Task[] diagnostics;
        lock (gate) diagnostics = diagnosticTasks.ToArray();
        // These tasks only produce diagnostic traffic. Cancellation/failure
        // is not a resource-close failure, but every producer must finish.
        try { await Task.WhenAll(diagnostics); } catch (Exception) { }

        // Every reader/writer has joined, including when a path failed to
        // release its own transport. Finish independent local cleanup while
        // retaining failed path owners and reporting the failure to Runner.
        lock (gate) {
            foreach (var peer in peers.Values) Cleanup("session-keys", peer.Link.Dispose);
            peers.Clear();
        }
        Cleanup("local-socket", socket.Dispose);
        Cleanup("adapter-close", adapter.Dispose);
        Cleanup("cancellation-source", stop.Dispose);
        if (failures.Count > 0) throw new AggregateException("路由器资源回收未全部完成", failures);
    }
}
