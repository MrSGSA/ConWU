using Android.OS;
using System.Runtime.InteropServices;
using StreamLink.Core;

namespace ConWU.Android;

// VpnService owns creation. Nonblocking TUN + bounded poll permits shutdown
// without closing/reusing a descriptor while another thread is reading it.
sealed class AndroidTunAdapter : IPacketAdapter
{
    [StructLayout(LayoutKind.Sequential)]struct PollDescriptor{public int Descriptor;public short Events,Returned;}
    [DllImport("libc",EntryPoint="poll",SetLastError=true)]static extern int Poll(ref PollDescriptor descriptor,nuint count,int timeout);
    [DllImport("libc",EntryPoint="read",SetLastError=true)]static extern nint ReadNative(int descriptor,[Out]byte[] buffer,nuint count);
    [DllImport("libc",EntryPoint="write",SetLastError=true)]static extern nint WriteNative(int descriptor,byte[] buffer,nuint count);
    [DllImport("libc",EntryPoint="close")]static extern int CloseNative(int descriptor);
    readonly object readGate=new(),writeGate=new();
    int descriptor,stopping;
    long readPackets,readBytes,writtenPackets,writtenBytes;
    public AndroidTunAdapter(ParcelFileDescriptor handle){descriptor=handle.DetachFd();handle.Dispose();}
    public PacketAdapterDescriptor Descriptor=>new("android-vpn",2,MeshLink.Mtu,true,true,false);
    public PacketAdapterStatistics Statistics=>new(Interlocked.Read(ref readPackets),Interlocked.Read(ref readBytes),Interlocked.Read(ref writtenPackets),Interlocked.Read(ref writtenBytes),0,0,0,Volatile.Read(ref stopping)!=0);
    public int Read(byte[] buffer)=>Read(buffer,CancellationToken.None);
    public int Read(byte[] buffer,CancellationToken token)
    {
        lock(readGate)while(Volatile.Read(ref stopping)==0){
            token.ThrowIfCancellationRequested();var poll=new PollDescriptor{Descriptor=descriptor,Events=1};
            int ready=Poll(ref poll,1,250);
            if(Volatile.Read(ref stopping)!=0)return 0;
            if(ready==0)continue;
            if(ready<0){if(Marshal.GetLastPInvokeError()==4)continue;throw new IOException("系统 VPN 读取等待失败");}
            if((poll.Returned&1)==0)throw new IOException("系统 VPN 接口已关闭");
            int count=(int)ReadNative(descriptor,buffer,(nuint)buffer.Length);
            if(count<0){int error=Marshal.GetLastPInvokeError();if(error is 4 or 11)continue;throw new IOException("系统 VPN 读取失败");}
            if(count>0){Interlocked.Increment(ref readPackets);Interlocked.Add(ref readBytes,count);}return count;
        }
        return 0;
    }
    public bool Write(byte[] packet)
    {
        lock(writeGate){if(Volatile.Read(ref stopping)!=0||descriptor<0)return false;int count=(int)WriteNative(descriptor,packet,(nuint)packet.Length);
            if(count!=packet.Length)return false;Interlocked.Increment(ref writtenPackets);Interlocked.Add(ref writtenBytes,count);return true;}
    }
    public void Stop()=>Interlocked.Exchange(ref stopping,1);
    public void Dispose(){Stop();lock(readGate)lock(writeGate){int owned=Interlocked.Exchange(ref descriptor,-1);if(owned>=0)CloseNative(owned);}}
}
