using System.Buffers.Binary;
using System.IO.Pipes;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;

namespace StreamLink.Core;

public sealed record LegacyBusinessEgressStats(long OfferedPackets,long OfferedBytes,long InjectedPackets,long InjectedBytes,long RejectedPackets,int Outstanding,int PeakOutstanding,string Failure);

// Full outer IPv4/TCP business frames; no reliable application retransmission.
// The only business queue is the shared EgressPacer. Pipe writes/receipts have
// explicit bounded in-flight storage and never wait for control permits.
[SupportedOSPlatform("windows")]
internal sealed class LegacyEgressChannel : IDisposable
{
    readonly NamedPipeServerStream pipe;
    readonly byte[] authorization;
    readonly EgressPacer pacer;
    readonly Dictionary<int,EgressPacer.Flow> flows=[];
    readonly MeshProfile profile;
    readonly IPEndPoint? remote;
    readonly int serverPort;
    readonly CancellationTokenSource stop=new();
    CancellationTokenSource epochStop=new();
    readonly Channel<byte[]> receipts=Channel.CreateBounded<byte[]>(new BoundedChannelOptions(64){FullMode=BoundedChannelFullMode.Wait,SingleReader=true,SingleWriter=false});
    readonly Func<ReadOnlyMemory<byte>,bool>? testInject;
    WinDivertEgressInjector? injector;
    readonly string dll;
    readonly LegacyRouteEvidence route;
    Task running=Task.CompletedTask;
    int outstanding,peak,disposed;
    long offered,bytes,injected,injectedBytes,rejected;
    string failure="";
    internal string Name{get;}="StreamLink.Egress."+Guid.NewGuid().ToString("N");
    internal bool Failed=>Volatile.Read(ref failure).Length>0;
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetNamedPipeClientProcessId(SafePipeHandle handle,out uint pid);
    internal LegacyEgressChannel(string authorization,EgressPacer pacer,MeshProfile profile,IPEndPoint target,bool server,int port,string dll,LegacyRouteEvidence route,Func<ReadOnlyMemory<byte>,bool>? testInject=null)
    {
        this.authorization=Convert.FromHexString(authorization);this.pacer=pacer;this.dll=dll;this.testInject=testInject;
        this.route=route;
        this.profile=profile;
        remote=server?null:target;serverPort=server?port:0;
        pipe=new(Name,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly|PipeOptions.FirstPipeInstance,8192,4096);
    }
    internal LegacyBusinessEgressStats Snapshot()=>new(Interlocked.Read(ref offered),Interlocked.Read(ref bytes),Interlocked.Read(ref injected),Interlocked.Read(ref injectedBytes),Interlocked.Read(ref rejected),Volatile.Read(ref outstanding),Volatile.Read(ref peak),Volatile.Read(ref failure));
    internal void Start(int pid)=>running=Run(pid);
    async Task WriteReceipts()
    {
        try{await foreach(var frame in receipts.Reader.ReadAllAsync(stop.Token)){
            using var limit=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);limit.CancelAfter(1000);await pipe.WriteAsync(frame,limit.Token);
        }}catch(Exception ex)when(!stop.IsCancellationRequested){Volatile.Write(ref failure,"ReceiptWriter:"+ex.GetType().Name);stop.Cancel();}
    }
    sealed class SendReceipt(ulong sequence,int length,string outlet){internal readonly ulong Sequence=sequence;internal readonly int Length=length;internal readonly string Outlet=outlet;internal int Completed;}
    void Complete(SendReceipt receipt,bool sent){if(Interlocked.Exchange(ref receipt.Completed,1)==0)Receipt(receipt.Sequence,receipt.Length,sent);}
    void Receipt(ulong sequence,int length,bool sent)
    {
        var frame=new byte[16];BinaryPrimitives.WriteUInt64LittleEndian(frame,sequence);frame[8]=(byte)(sent?0:1);BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(12),length);
        if(!receipts.Writer.TryWrite(frame)&&!stop.IsCancellationRequested){Volatile.Write(ref failure,"ReceiptCapacityExceeded");stop.Cancel();}
        if(length>0)Interlocked.Decrement(ref outstanding);
    }
    async Task Run(int pid)
    {
        Task writer=Task.CompletedTask;
        try{
            using var ready=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);ready.CancelAfter(5000);
            await pipe.WaitForConnectionAsync(ready.Token);
            if(!GetNamedPipeClientProcessId(pipe.SafePipeHandle,out var actual)||actual!=pid)throw new IOException("Legacy egress child identity rejected");
            var hello=new byte[64];await pipe.ReadExactlyAsync(hello,ready.Token);
            if(!CryptographicOperations.FixedTimeEquals(hello,authorization))throw new IOException("Legacy egress authorization rejected");
            await pipe.WriteAsync(authorization,ready.Token);CryptographicOperations.ZeroMemory(hello);writer=WriteReceipts();
            var header=new byte[24];ulong last=0,epoch=0;
            while(true){
                await pipe.ReadExactlyAsync(header,stop.Token);
                int length=BinaryPrimitives.ReadInt32LittleEndian(header);ulong sequence=BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(4)),generation=BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(12));int peer=header[20];
                if(sequence<=last||header[21]!=0||header[22]!=0||header[23]!=0)throw new IOException("Legacy egress frame identity rejected");last=sequence;
                if(length==0){
                    if(generation!=epoch+1||peer!=0)throw new IOException("Legacy egress fence rejected");
                    epochStop.Cancel();foreach(var retired in flows.Values)retired.Dispose();flows.Clear();epochStop.Dispose();epochStop=new();epoch=generation;
                    Receipt(sequence,0,true);continue;
                }
                if(length is <40 or >6144||generation!=epoch||peer==profile.Self.Slot||profile.Directory?.Members.Any(m=>m.Slot==peer)!=true)throw new IOException("Legacy egress ownership rejected");
                var packet=new byte[length];await pipe.ReadExactlyAsync(packet,stop.Token);
                if(!Validate(packet,generation,out string outlet))throw new IOException("Legacy egress outer packet or prepared route rejected");
                Interlocked.Increment(ref offered);Interlocked.Add(ref bytes,length);int active=Interlocked.Increment(ref outstanding);peak=Math.Max(peak,active);
                if(active>64)throw new IOException("Legacy egress in-flight bound exceeded");
                if(!flows.TryGetValue(peer,out var flow)){
                    flow=pacer.RegisterRouted("slot:"+peer,context=>((SendReceipt)context!).Outlet,(data,context)=>{
                        bool sent=false;
                        try{sent=testInject?.Invoke(data)??(injector??=new(dll)).Inject(data.Span);
                            if(sent){Interlocked.Increment(ref injected);Interlocked.Add(ref injectedBytes,data.Length);}else Interlocked.Increment(ref rejected);
                            return sent;
                        }finally{Complete((SendReceipt)context!,sent);}
                    });flows.Add(peer,flow);
                }
                // A completion also reports queue eviction/cancellation. A send
                // callback reports itself; rejected queue entries never retry.
                var completion=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var receipt=new SendReceipt(sequence,length,outlet);
                if(!flow.TrySend(packet,length,receipt,token:epochStop.Token,completion:completion)){Interlocked.Increment(ref rejected);Complete(receipt,false);}
                else _=ObserveCompletion(completion.Task,receipt);
            }
        }catch(Exception)when(stop.IsCancellationRequested){}
        catch(Exception ex){Volatile.Write(ref failure,ex.GetType().Name+":"+ex.Message);}
        finally{stop.Cancel();epochStop.Cancel();foreach(var flow in flows.Values)flow.Dispose();flows.Clear();receipts.Writer.TryComplete();pipe.Dispose();try{await writer;}catch{}injector?.Dispose();}
    }
    async Task ObserveCompletion(Task completion,SendReceipt receipt)
    {
        try{await completion;}catch{if(Volatile.Read(ref receipt.Completed)==0)Interlocked.Increment(ref rejected);Complete(receipt,false);}
    }
    bool Validate(byte[] packet,ulong generation,out string outlet)
    {
        outlet="Unresolved";
        if(packet[0]>>4!=4||packet[9]!=6||!TcpPacketValidation.Checksums(packet))return false;
        int h=(packet[0]&15)*4;var source=new IPAddress(packet.AsSpan(12,4));var target=new IPEndPoint(new IPAddress(packet.AsSpan(16,4)),BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(h+2)));
        if((serverPort!=0&&BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(h))!=serverPort)||(remote!=null&&!target.Equals(remote))||source.Equals(IPAddress.Any))return false;
        if(!route.Use(generation,new(source,BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(h))),target,out var witness))return false;
        outlet=witness?.PacingKey??"Unresolved";return true;
    }
    public void Dispose(){if(Interlocked.Exchange(ref disposed,1)!=0)return;stop.Cancel();pipe.Dispose();running.GetAwaiter().GetResult();epochStop.Dispose();stop.Dispose();CryptographicOperations.ZeroMemory(authorization);}
}
