using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink;

sealed class DesktopBackend : IAsyncDisposable
{
    ControlWorker? local;
    readonly SemaphoreSlim gate = new(1, 1);
    public bool IsService => ServiceInstaller.Installed;
    public async Task<ControlReply> Call(ControlRequest request, CancellationToken token = default)
    {
        // Status/cancel can bypass long management operations. The server owns
        // immutable snapshots and still authenticates every pipe connection.
        if(request.Command is "status" or "cancel") {
            if(IsService)return await ServiceProtocol.Call(request,token);
            if(local is {} ready)return await ready.Handle(request,token);
        }
        await gate.WaitAsync(token);
        try {
            if (IsService) { if (request.Command != "status") await ServiceInstaller.StartIfNeeded(); return await ServiceProtocol.Call(request, token); }
            if (local == null) { local = await Task.Run(() => new ControlWorker(), token); local.StartLocal(); }
            return await local.Handle(request,token);
        } finally { gate.Release(); }
    }
    public async Task ReleaseLocal()
    {
        await gate.WaitAsync();
        try { if (local != null) { await local.StopLocal(); local.Dispose(); local = null; } }
        finally { gate.Release(); }
    }
    public async ValueTask DisposeAsync() { try{await ReleaseLocal();}catch{local?.Dispose();throw;}finally{gate.Dispose();} }
}
