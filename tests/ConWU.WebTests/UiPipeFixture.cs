using System.IO.Pipes;
using System.Reflection;
using System.Security.Principal;
using StreamLink.Core;
using StreamLink.Service;

// Real restricted pipe and ServeUi acknowledgement, isolated from daily SCM.
sealed class UiPipeFixture : IAsyncDisposable
{
    readonly CancellationTokenSource stop = new();
    readonly Task server;
    readonly SemaphoreSlim mutationGate;
    readonly bool defer;
    public UiPipeFixture(ControlWorker worker, bool defer)
    {
        this.defer = defer;
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        mutationGate = (SemaphoreSlim)typeof(ControlWorker).GetField("requests", flags)!.GetValue(worker)!;
        server = (Task)typeof(ControlWorker).GetMethod("RunUiControl", flags)!.Invoke(worker, [stop.Token])!;
    }
    public async Task<UiControlReply> Call(UiControlRequest request, CancellationToken token)
    {
        bool hold = defer && request.Method != "status";
        if (hold) await mutationGate.WaitAsync(token);
        try {
            using var pipe = new NamedPipeClientStream(".", UiControlProtocol.PipeName, PipeDirection.InOut,
                PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
            await pipe.ConnectAsync(3000, token);
            await ServiceProtocol.Write(pipe, request, token);
            // Keep the service queue occupied past its 700ms acknowledgement.
            if (hold) await Task.Delay(1100, token);
            return await ServiceProtocol.Read<UiControlReply>(pipe, token);
        } finally { if (hold) mutationGate.Release(); }
    }
    public async ValueTask DisposeAsync() { stop.Cancel(); await server; stop.Dispose(); }
}
