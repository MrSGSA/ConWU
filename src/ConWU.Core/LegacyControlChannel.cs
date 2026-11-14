using System.Buffers.Binary;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace StreamLink.Core;

public sealed record LegacyControlChannelReport(long Requests,long Admitted,long BudgetDenied,long WindowDenied,long RouteRejected,long Expired,
    long MaximumRouteMs,long MaximumAdmissionMs,long MaximumRequestAgeMs,string Stage,string Failure);

[SupportedOSPlatform("windows")]
internal sealed class LegacyControlChannel : IDisposable
{
    readonly NamedPipeServerStream pipe;
    readonly CancellationTokenSource stop = new();
    readonly byte[] authorization = RandomNumberGenerator.GetBytes(64);
    readonly Guid resource;
    readonly byte protocol;
    readonly int port;
    readonly LegacyControlGovernor governor;
    readonly LegacyRouteEvidence? route;
    Task running = Task.CompletedTask;
    int failed, disposed, authorized;
    long requests,admitted,budgetDenied,windowDenied,routeRejected,expired,maximumRouteMs,maximumAdmissionMs,maximumRequestAgeMs;
    string stage="WaitingForChild";
    internal string Failure { get; private set; } = "";
    internal string Name { get; } = "StreamLink.Legacy." + Guid.NewGuid().ToString("N");
    internal string Authorization => Convert.ToHexString(authorization);
    internal bool Failed => Volatile.Read(ref failed) != 0;
    internal bool Authorized => Volatile.Read(ref authorized) != 0;
    internal LegacyControlChannelReport Snapshot()=>new(Interlocked.Read(ref requests),Interlocked.Read(ref admitted),Interlocked.Read(ref budgetDenied),
        Interlocked.Read(ref windowDenied),Interlocked.Read(ref routeRejected),Interlocked.Read(ref expired),Interlocked.Read(ref maximumRouteMs),
        Interlocked.Read(ref maximumAdmissionMs),Interlocked.Read(ref maximumRequestAgeMs),Volatile.Read(ref stage),Failure);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);
    internal LegacyControlChannel(Guid resource, bool tcp, int serverPort, LegacyControlGovernor? governor = null,LegacyRouteEvidence? route=null)
    {
        this.resource = resource; protocol = tcp ? (byte)6 : (byte)17; port = serverPort;
        this.governor = governor ?? LegacyControlGovernor.Shared;
        this.route=route;
        pipe = new(Name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance, 4096, 4096);
    }
    internal void Start(int pid) => running = Run(pid);
    async Task Run(int pid)
    {
        try {
            using var ready = CancellationTokenSource.CreateLinkedTokenSource(stop.Token); ready.CancelAfter(5000);
            await pipe.WaitForConnectionAsync(ready.Token);
            Volatile.Write(ref stage,"AuthorizeChild");
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint actual) || actual != pid) throw new IOException("Legacy control process rejected");
            var hello = new byte[64]; await pipe.ReadExactlyAsync(hello, ready.Token);
            if (!CryptographicOperations.FixedTimeEquals(hello, authorization)) throw new IOException("Legacy control authorization rejected");
            Volatile.Write(ref authorized, 1);
            await pipe.WriteAsync(authorization, ready.Token);
            var frame = new byte[56]; var reply = new byte[16]; ulong last = 0;
            while (true) {
                Volatile.Write(ref stage,"ReadRequest");
                await pipe.ReadExactlyAsync(frame, stop.Token);
                Volatile.Write(ref stage,"ValidateRequest");
                var request = LegacyControlRequest.Decode(frame, protocol, port);
                if (request.Sequence <= last) throw new IOException("Legacy control sequence rejected");
                last = request.Sequence;
                Interlocked.Increment(ref requests);
                Volatile.Write(ref stage,"PrepareRoute");
                long routeBegan=Environment.TickCount64;
                bool routeReady=route?.Prepare(request.Capture,new(request.Source,request.SourcePort),new(request.Target,request.TargetPort),out _)??true;
                maximumRouteMs=Math.Max(maximumRouteMs,Environment.TickCount64-routeBegan);
                Volatile.Write(ref stage,"AdmitRequest");
                long admissionBegan=Environment.TickCount64;
                byte result =routeReady?await governor.Admit(resource, request, stop.Token):(byte)2;
                maximumAdmissionMs=Math.Max(maximumAdmissionMs,Environment.TickCount64-admissionBegan);
                maximumRequestAgeMs=Math.Max(maximumRequestAgeMs,Environment.TickCount64-request.QueuedAt);
                if(!routeReady)Interlocked.Increment(ref routeRejected);
                else switch(result){case 0:Interlocked.Increment(ref admitted);break;case 1:Interlocked.Increment(ref budgetDenied);break;
                    case 2:Interlocked.Increment(ref windowDenied);break;case 3:Interlocked.Increment(ref expired);break;}
                reply.AsSpan().Clear(); BinaryPrimitives.WriteUInt64LittleEndian(reply, request.Sequence); reply[8] = result;
                Volatile.Write(ref stage,"WriteReply");
                await pipe.WriteAsync(reply, stop.Token);
            }
        } catch (Exception) when (stop.IsCancellationRequested) { }
        catch (Exception ex) { Failure = stage+":"+ex.GetType().Name+":0x"+ex.HResult.ToString("X8"); Volatile.Write(ref failed, 1); }
        finally { pipe.Dispose(); }
    }
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stop.Cancel(); pipe.Dispose(); running.GetAwaiter().GetResult();
        governor.Retire(resource); CryptographicOperations.ZeroMemory(authorization); stop.Dispose();
    }
}
