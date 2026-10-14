using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

if(args is ["--contract-test",var contractOutput]) {
    if(Marshal.SizeOf<KernelIo.Overlapped>()!=32)throw new Exception("x64 OVERLAPPED layout");
    var packet=Packets.Inbound(IPAddress.Parse("10.254.242.2"),IPAddress.Parse("10.254.242.1"),49173,49174,[1,2,3]);
    if(packet.Length!=31||Packets.Payload(packet,49174)?.Length!=3)throw new Exception("packet framing");
    File.WriteAllText(contractOutput,JsonSerializer.Serialize(new {status="Pass",scope="Tool packet/layout contracts; no kernel handle opened",checks=2}));return;
}
if(args.Length!=3 || args[0] is not ("--run" or "--permission-check"))throw new ArgumentException("--run/--permission-check protected-lab-plan.json fresh-result.json; never run on daily hosts");
var plan=JsonSerializer.Deserialize<LabPlan>(File.ReadAllText(args[1]))??throw new IOException("Missing plan");
string output=Path.GetFullPath(args[2]);if(File.Exists(output))throw new IOException("Never overwrite kernel evidence");
string machine=(string?)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography","MachineGuid",null)??"";
string model=(string?)Registry.GetValue(@"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS","SystemProductName",null)??"";
if(!plan.AuthorizedRecoverableLab||!plan.RecoveryConfirmed||plan.GuestMachineGuid!=machine||plan.HostMachineGuid==machine||
    plan.HostMachineGuid.Length==0||!new[]{"Virtual Machine","VMware Virtual Platform","VirtualBox","KVM","Standard PC"}.Any(s=>model.Contains(s,StringComparison.OrdinalIgnoreCase))||
    plan.InterfaceIndex==0||plan.PackageHash.Length!=64||plan.RunId==Guid.Empty)throw new IOException("Explicit isolated, recoverable guest identity required; no device opened");
bool admin=new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
string device=@"\\.\StreamLinkTun-"+plan.InterfaceIndex;
if(args[0]=="--permission-check"){
    if(admin)throw new IOException("Permission negative must run as standard user inside the same lab guest");
    using var denied=KernelIo.Open(device);int error=Marshal.GetLastPInvokeError();
    bool pass=denied.IsInvalid&&error==5;
    File.WriteAllText(output,JsonSerializer.Serialize(new{schemaVersion=1,tool="StreamLink.TunKernelTests",evidenceLevel="DriverKernelIO",plan.RunId,plan.PackageHash,machine,
        permissions=pass?"Pass":"Fail",openError=error,admin=false,device,scope="Actual standard-user CreateFile denial; missing device is not accepted"},new JsonSerializerOptions{WriteIndented=true}));
    Environment.ExitCode=pass?0:1;return;
}
if(!admin)throw new IOException("Admin is required inside the authorized lab guest");
var rows=new List<object>();string failure="";bool ioPass=false,cancelPass=false,cleanupPass=false;var watch=Stopwatch.StartNew();
Directory.CreateDirectory(Path.GetDirectoryName(output)!);
void Stage(string phase,object? data=null){File.AppendAllText(output+".jsonl",JsonSerializer.Serialize(new{phase,elapsedMs=watch.ElapsedMilliseconds,data})+Environment.NewLine);}
KernelIo? kernel=null;
try{
    kernel=new(device);var info=kernel.Control(0x00126404,32);
    if(BinaryPrimitives.ReadUInt32LittleEndian(info)!=32||BinaryPrimitives.ReadUInt32LittleEndian(info.AsSpan(4))!=1||
        BinaryPrimitives.ReadUInt32LittleEndian(info.AsSpan(8))!=1280||BinaryPrimitives.ReadUInt32LittleEndian(info.AsSpan(24))!=plan.InterfaceIndex)throw new IOException("Actual loaded ABI/index mismatch");
    Stage("loaded-info",new {index=plan.InterfaceIndex,luid=BinaryPrimitives.ReadUInt64LittleEndian(info.AsSpan(16))});
    using(var second=KernelIo.Open(device)){if(!second.IsInvalid)throw new IOException("Second kernel owner was allowed");}
    var local=IPAddress.Parse("10.254.242.1");var peer=IPAddress.Parse("10.254.242.2");
    using var udp=new UdpClient(new IPEndPoint(local,49174));udp.Client.DontFragment=true;
    for(int i=0;i<10;i++){
        byte[] payload=new byte[1252];Random.Shared.NextBytes(payload);
        using var read=kernel.BeginRead();await udp.SendAsync(payload,new IPEndPoint(peer,49173));
        byte[]? seen=null;for(int probe=0;probe<8;probe++){
            var result=read.Complete(TimeSpan.FromSeconds(2));if(result.Error!=0)throw new Win32Exception(result.Error);
            seen=Packets.Payload(result.Bytes,49173);if(seen!=null)break;
            if(probe==7)throw new IOException("OS -> NDIS -> READ full-MTU packet missing");
            // Other OS control packets are not a test pass. A fresh READ is
            // needed, so fail with raw evidence rather than hiding them.
            throw new IOException("Unexpected OS packet; isolate guest traffic before retry");
        }
        if(seen==null||!seen.SequenceEqual(payload))throw new IOException("Actual outbound payload mismatch");
        kernel.Write(Packets.Inbound(peer,local,49173,49174,payload));
        using var limit=new CancellationTokenSource(2000);var inbound=await udp.ReceiveAsync(limit.Token);
        if(!inbound.Buffer.SequenceEqual(payload)||!inbound.RemoteEndPoint.Address.Equals(peer))throw new IOException("WRITE -> NDIS -> OS full-MTU payload mismatch");
        rows.Add(new{kind="fullMtu",iteration=i,bytes=1280});
    }ioPass=true;Stage("kernel-io-pass");
    ulong cancelledBefore=BinaryPrimitives.ReadUInt64LittleEndian(kernel.Control(0x00126408,80).AsSpan(56));
    void Drain(){for(int j=0;j<64;j++){uint queued=BinaryPrimitives.ReadUInt32LittleEndian(kernel.Control(0x00126408,80).AsSpan(64));if(queued==0)return;using var r=kernel.BeginRead();var c=r.Complete(TimeSpan.FromSeconds(2));if(c.Error!=0)throw new Win32Exception(c.Error);}throw new IOException("Packet queue did not drain within its declared bound");}
    Drain();
    for(int i=0;i<30;i++){
        using var pending=kernel.BeginRead();
        Task sending=Task.Run(async()=>{if((i&1)==0)await Task.Delay(1);await udp.SendAsync(new byte[32],new IPEndPoint(peer,49173));});
        Task cancel=Task.Run(()=>pending.Cancel());await Task.WhenAll(sending,cancel);
        var completion=pending.Complete(TimeSpan.FromSeconds(2));
        if(completion.Error is not (0 or 995))throw new Win32Exception(completion.Error);
        if(!pending.CompletionObservedOnce)throw new IOException("Overlapped completion not uniquely observed");
        rows.Add(new{kind="cancel-race",iteration=i,completion.Error,completionBytes=completion.Bytes.Length});
        Drain();
    }
    // CancelIoEx must complete actual pending requests, including a batch;
    // no delegate/model implementation is used here.
    var batch=new List<KernelIo.Operation>();
    try{for(int i=0;i<16;i++)batch.Add(kernel.BeginRead());
        uint actualPending=BinaryPrimitives.ReadUInt32LittleEndian(kernel.Control(0x00126408,80).AsSpan(72));
        if(actualPending==0)throw new IOException("No actual queued CSQ IRP was observed; cancellation coverage not proved");
        Stage("actual-csq-pending",new{actualPending});foreach(var op in batch)op.Cancel();foreach(var op in batch){var r=op.Complete(TimeSpan.FromSeconds(2));if(r.Error is not (0 or 995))throw new Win32Exception(r.Error);}}
    finally{foreach(var op in batch)op.Dispose();}
    var stats=kernel.Control(0x00126408,80);uint pendingCount=BinaryPrimitives.ReadUInt32LittleEndian(stats.AsSpan(72));
    if(pendingCount!=0)throw new IOException("Actual CSQ pending read count did not drain");
    if(BinaryPrimitives.ReadUInt64LittleEndian(stats.AsSpan(56))<=cancelledBefore)throw new IOException("No actual kernel cancellation counter advance");
    cancelPass=true;Stage("cancel-and-csq-drained",new{pendingCount});
    kernel.Dispose();kernel=null;
    using(var reopened=new KernelIo(device)){_=reopened.Control(0x00126404,32);}cleanupPass=true;Stage("closed-and-reopened");
}catch(Exception ex){failure=ex.ToString();Stage("fail",new{failure});}
finally{
    // An incomplete operation keeps its pinned buffer and OVERLAPPED alive.
    // Do not unload anything or free pending storage to manufacture completion.
    if(kernel!=null){try{kernel.Dispose();}catch(Exception ex){failure+="\n"+ex;}}
    File.WriteAllText(output,JsonSerializer.Serialize(new {schemaVersion=1,tool="StreamLink.TunKernelTests",evidenceLevel="DriverKernelIO",plan.RunId,plan.PackageHash,
        machine,model,device,status=failure.Length==0?"Pass":"Fail",kernelIo=ioPass?"Pass":"Fail",cancellation=cancelPass?"Pass":"Fail",cleanup=cleanupPass?"Pass":"Fail",
        permissions="SeparateStandardUserRunRequired",verifier="SeparateBootedTargetedVerifierRunRequired",rows,failure,
        scope="Actual installed research device, IRPs, NDIS and OS UDP; guest evidence only. No host loading or approval generated by this executable."},new JsonSerializerOptions{WriteIndented=true}));
}
Environment.ExitCode=failure.Length==0?0:1;

sealed record LabPlan(Guid RunId,string GuestMachineGuid,string HostMachineGuid,uint InterfaceIndex,string PackageHash,bool AuthorizedRecoverableLab,bool RecoveryConfirmed);
sealed class KernelIo:IDisposable
{
    [StructLayout(LayoutKind.Sequential)]public struct Overlapped{public IntPtr Internal,InternalHigh;public uint Offset,OffsetHigh;public IntPtr Event;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFile(string p,uint a,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool ReadFile(SafeFileHandle h,IntPtr b,uint n,out uint count,IntPtr o);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool WriteFile(SafeFileHandle h,IntPtr b,uint n,out uint count,IntPtr o);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool DeviceIoControl(SafeFileHandle h,uint code,IntPtr input,uint n,IntPtr output,uint capacity,out uint count,IntPtr o);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool CancelIoEx(SafeFileHandle h,IntPtr o);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetOverlappedResult(SafeFileHandle h,IntPtr o,out uint n,bool wait);
    public static SafeFileHandle Open(string device)=>CreateFile(device,0xC0000000,0,IntPtr.Zero,3,0x40000000,IntPtr.Zero);
    readonly SafeFileHandle handle;readonly HashSet<Operation> operations=[];
    public KernelIo(string device){handle=Open(device);if(handle.IsInvalid)throw new Win32Exception(Marshal.GetLastPInvokeError());}
    public Operation BeginRead()=>new(this,new byte[1280],0,false);
    public byte[] Control(uint code,int size){using var o=new Operation(this,new byte[size],code,false);var r=o.Complete(TimeSpan.FromSeconds(2));if(r.Error!=0)throw new Win32Exception(r.Error);if(r.Bytes.Length!=size)throw new IOException("IOCTL length mismatch");return r.Bytes;}
    public void Write(byte[] bytes){using var o=new Operation(this,bytes,0,true);var r=o.Complete(TimeSpan.FromSeconds(2));if(r.Error!=0||r.Bytes.Length!=bytes.Length)throw new IOException("Kernel WRITE failure: "+r.Error);}
    public void Dispose(){if(operations.Count!=0)throw new IOException("Outstanding IRP resources retained until owned supervisor ends process");handle.Dispose();}
    public sealed class Operation:IDisposable
    {
        readonly KernelIo owner;readonly byte[] bytes;readonly GCHandle pinned;readonly IntPtr overlapped;readonly ManualResetEvent completed=new(false);
        bool observed;int immediateError;uint immediateCount;bool pending;
        public bool CompletionObservedOnce=>observed;
        public Operation(KernelIo k,byte[] buffer,uint code,bool writing){owner=k;bytes=buffer;pinned=GCHandle.Alloc(buffer,GCHandleType.Pinned);overlapped=Marshal.AllocHGlobal(32);
            Marshal.StructureToPtr(new Overlapped{Event=completed.SafeWaitHandle.DangerousGetHandle()},overlapped,false);owner.operations.Add(this);
            bool ok=code!=0?DeviceIoControl(k.handle,code,IntPtr.Zero,0,pinned.AddrOfPinnedObject(),(uint)bytes.Length,out immediateCount,overlapped):
                writing?WriteFile(k.handle,pinned.AddrOfPinnedObject(),(uint)bytes.Length,out immediateCount,overlapped):ReadFile(k.handle,pinned.AddrOfPinnedObject(),(uint)bytes.Length,out immediateCount,overlapped);
            immediateError=ok?0:Marshal.GetLastPInvokeError();pending=immediateError==997;
        }
        public void Cancel(){if(!CancelIoEx(owner.handle,overlapped)&&Marshal.GetLastPInvokeError()!=1168)throw new Win32Exception(Marshal.GetLastPInvokeError());}
        public (byte[] Bytes,int Error) Complete(TimeSpan deadline){if(observed)throw new IOException("Duplicate user completion observation");int error=immediateError;uint count=immediateCount;
            if(pending){if(!completed.WaitOne(deadline))throw new TimeoutException("Actual pending IRP not completed; pinned state retained");bool ok=GetOverlappedResult(owner.handle,overlapped,out count,false);error=ok?0:Marshal.GetLastPInvokeError();}
            observed=true;owner.operations.Remove(this);return(bytes.AsSpan(0,checked((int)Math.Min(count,(uint)bytes.Length))).ToArray(),error);
        }
        public void Dispose(){if(!observed)return;Marshal.FreeHGlobal(overlapped);pinned.Free();completed.Dispose();}
    }
}
static class Packets
{
    public static byte[]? Payload(byte[] p,int port){if(p.Length<28||(p[0]>>4)!=4||p[9]!=17)return null;int ip=(p[0]&15)*4;if(ip<20||p.Length<ip+8||BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(ip+2))!=port)return null;return p.AsSpan(ip+8).ToArray();}
    public static byte[] Inbound(IPAddress src,IPAddress dst,int source,int target,byte[] payload){var p=new byte[28+payload.Length];p[0]=0x45;BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2),(ushort)p.Length);p[8]=64;p[9]=17;src.GetAddressBytes().CopyTo(p,12);dst.GetAddressBytes().CopyTo(p,16);BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20),(ushort)source);BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22),(ushort)target);BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(24),(ushort)(8+payload.Length));payload.CopyTo(p,28);uint sum=0;for(int i=0;i<20;i+=2)sum+=BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i));while(sum>65535)sum=(sum&65535)+(sum>>16);BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10),(ushort)~sum);return p;}
}
