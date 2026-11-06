using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace StreamLink.Core;

// Non-persistent kernel TUN: closing the sole fd removes only this interface.
// No default route, DNS setting or foreign interface is changed.
public sealed class LinuxTunAdapter : IPacketAdapter
{
    [DllImport("libc",SetLastError=true)]static extern int open(string path,int flags);
    [DllImport("libc",SetLastError=true)]static extern int ioctl(int fd,nuint request,byte[] value);
    [DllImport("libc",SetLastError=true)]static extern nint read(int fd,byte[] buffer,nuint length);
    [DllImport("libc",SetLastError=true)]static extern nint write(int fd,byte[] buffer,nuint length);
    [DllImport("libc",SetLastError=true)]static extern int close(int fd);
    [StructLayout(LayoutKind.Sequential)]struct PollFd{public int Fd;public short Events;public short Returned;}
    [DllImport("libc",SetLastError=true)]static extern int poll(ref PollFd descriptor,nuint count,int milliseconds);
    readonly ReaderWriterLockSlim gate=new();int fd=-1,stopping;long readPackets,readBytes,writtenPackets,writtenBytes,dropped,truncated,waits;
    public string Name {get;}
    public PacketAdapterDescriptor Descriptor=>new(PacketAdapterProviders.LinuxTun,2,MeshLink.Mtu,true,true,false);
    public PacketAdapterStatistics Statistics=>new(Interlocked.Read(ref readPackets),Interlocked.Read(ref readBytes),Interlocked.Read(ref writtenPackets),Interlocked.Read(ref writtenBytes),Interlocked.Read(ref dropped),Interlocked.Read(ref truncated),Interlocked.Read(ref waits),Volatile.Read(ref stopping)!=0);
    public LinuxTunAdapter(string address,CancellationToken token=default) {
        if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException();
        MeshAddressing.ValidateAddress(address);token.ThrowIfCancellationRequested();
        using(var routes=JsonDocument.Parse(LinuxPlatform.Run("ip","-j","-4","route","show","table","main")))
            foreach(var route in routes.RootElement.EnumerateArray()) {
                if(!route.TryGetProperty("dst",out var dst))continue;var prefix=dst.GetString()??"";
                if(prefix=="default"||!IPNetwork.TryParse(prefix.Contains('/')?prefix:prefix+"/32",out var network))continue;
                var ours=new IPNetwork(IPAddress.Parse(MeshAddressing.Prefix(address)+".0"),24);
                if(network.Contains(IPAddress.Parse(address))||ours.Contains(network.BaseAddress))throw new IOException("虚拟网段与现有 Linux 路由重叠："+prefix);
            }
        Name="sl"+Guid.NewGuid().ToString("N")[..10];
        fd=open("/dev/net/tun",2|0x800|0x80000);
        if(fd<0)throw new Win32Exception(Marshal.GetLastPInvokeError(),"无法打开 /dev/net/tun，需要 TUN 与 CAP_NET_ADMIN 权限");
        try {
            var request=new byte[40];Encoding.ASCII.GetBytes(Name).CopyTo(request,0);
            System.Buffers.Binary.BinaryPrimitives.WriteInt16LittleEndian(request.AsSpan(16),unchecked((short)0x9001));
            if(ioctl(fd,0x400454ca,request)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError(),"创建独占 TUN 失败");
            token.ThrowIfCancellationRequested();
            LinuxPlatform.Run("ip","address","add",address+"/24","dev",Name);
            LinuxPlatform.Run("ip","link","set","dev",Name,"mtu",MeshLink.Mtu.ToString(),"up");
            token.ThrowIfCancellationRequested();PacketAdapterProviders.RequireProduction(Descriptor);
        }catch {close(fd);fd=-1;throw;}
    }
    public int Read(byte[] buffer) {
        gate.EnterReadLock();try{
            if(Volatile.Read(ref stopping)!=0)return 0;
            ObjectDisposedException.ThrowIf(fd<0,this);
            var descriptor=new PollFd{Fd=fd,Events=1};Interlocked.Increment(ref waits);
            int ready=poll(ref descriptor,1,100);
            if(ready<0){if(Marshal.GetLastPInvokeError()==4)return 0;throw new Win32Exception(Marshal.GetLastPInvokeError());}
            if(ready==0)return 0;
            int count=(int)read(fd,buffer,(nuint)buffer.Length);
            if(count<0){if(Marshal.GetLastPInvokeError() is 4 or 11)return 0;throw new Win32Exception(Marshal.GetLastPInvokeError());}
            if(count>MeshLink.Mtu){Interlocked.Increment(ref truncated);return 0;}
            if(count>0){Interlocked.Increment(ref readPackets);Interlocked.Add(ref readBytes,count);}return count;
        }finally{gate.ExitReadLock();}
    }
    public bool Write(byte[] packet) {
        gate.EnterReadLock();try{
            if(Volatile.Read(ref stopping)!=0)return false;ObjectDisposedException.ThrowIf(fd<0,this);
            if(packet.Length is <20 or >MeshLink.Mtu){Interlocked.Increment(ref truncated);return false;}
            int count=(int)write(fd,packet,(nuint)packet.Length);
            if(count<0&&Marshal.GetLastPInvokeError() is 4 or 11 or 105){Interlocked.Increment(ref dropped);return false;}
            if(count!=packet.Length)throw new Win32Exception(Marshal.GetLastPInvokeError(),"TUN 包写入未完成");
            Interlocked.Increment(ref writtenPackets);Interlocked.Add(ref writtenBytes,count);return true;
        }finally{gate.ExitReadLock();}
    }
    public void Stop()=>Interlocked.Exchange(ref stopping,1);
    public void Dispose(){Stop();gate.EnterWriteLock();try{if(fd>=0){close(fd);fd=-1;}}finally{gate.ExitWriteLock();}}
}
