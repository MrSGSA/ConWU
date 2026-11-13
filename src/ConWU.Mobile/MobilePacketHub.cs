using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using StreamLink.Core;

namespace ConWU.Mobile;

// One OS VPN interface, independent bounded queues for each authenticated pair.
// Peer virtual IPs select networks; this hub never forwards one pair to another.
public sealed class MobilePacketHub : IAsyncDisposable
{
    readonly IPacketAdapter tun;
    readonly Dictionary<uint,Port> ports=new();
    readonly object writeGate=new();
    readonly CancellationTokenSource stop=new();
    readonly Task reading;
    readonly uint? systemLocal;
    int disposed;
    public MobilePacketHub(IPacketAdapter tun,IEnumerable<MobileNetwork> networks,string? systemLocalIp=null)
    {
        this.tun=tun;
        try{
            systemLocal=systemLocalIp==null?null:Address(systemLocalIp);
            foreach(var network in networks){var port=new Port(this,network);if(!ports.TryAdd(Address(network.HostIp),port))throw new FormatException("多个网络使用了相同的目标虚拟 IP");}
            reading=Task.Factory.StartNew(Read,CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
        }catch{foreach(var port in ports.Values)port.Dispose();tun.Stop();tun.Dispose();stop.Dispose();throw;}
    }
    static uint Address(string ip)=>BinaryPrimitives.ReadUInt32BigEndian(IPAddress.Parse(ip).GetAddressBytes());
    public IPacketAdapter Adapter(string network)=>ports.Values.Single(p=>p.Network==network);
    public Task Completion=>reading;
    void Read()
    {
        byte[] buffer=new byte[MeshLink.Mtu+1];
        try{while(!stop.IsCancellationRequested){
            int count=tun.Read(buffer,stop.Token);
            if(count==0){if(stop.IsCancellationRequested)break;throw new IOException("系统 VPN 读取已结束");}
            if(count<20||count>MeshLink.Mtu||(buffer[0]>>4)!=4||(buffer[0]&15)<5||(buffer[0]&15)*4>count||BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(2))!=count)continue;
            uint target=BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(16)),source=BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(12));
            if(ports.TryGetValue(target,out var port)&&(systemLocal??port.Local)==source){
                var packet=buffer.AsSpan(0,count).ToArray();
                if(systemLocal!=null)MobileIpv4Translation.Rewrite(packet,12,port.Local);
                port.Enqueue(packet);
            }
        }}catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        finally{foreach(var port in ports.Values)port.Stop();}
    }
    sealed class Port : IPacketAdapter
    {
        readonly MobilePacketHub owner;
        readonly BlockingCollection<byte[]> incoming=new(128);
        readonly uint remote;
        int stopped;
        public string Network {get;}
        public uint Local {get;}
        public Port(MobilePacketHub owner,MobileNetwork network){this.owner=owner;Network=network.Id;Local=Address(network.Mesh.LocalIp);remote=Address(network.HostIp);}
        public PacketAdapterDescriptor Descriptor=>new("mobile-vpn-pair",2,MeshLink.Mtu,true,true,false);
        public void Enqueue(byte[] packet){if(Volatile.Read(ref stopped)==0)try{incoming.TryAdd(packet);}catch(InvalidOperationException){} }
        public int Read(byte[] buffer)=>Read(buffer,CancellationToken.None);
        public int Read(byte[] buffer,CancellationToken token){if(Volatile.Read(ref stopped)!=0)return 0;try{var packet=incoming.Take(token);if(Volatile.Read(ref stopped)!=0)return 0;packet.CopyTo(buffer,0);return packet.Length;}catch(InvalidOperationException){return 0;}}
        public bool Write(byte[] packet)
        {
            if(Volatile.Read(ref stopped)!=0||packet.Length is <20 or >MeshLink.Mtu||packet[0]>>4!=4||(packet[0]&15)<5||(packet[0]&15)*4>packet.Length||BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2))!=packet.Length||
                BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(12))!=remote||BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(16))!=Local)return false;
            if(owner.systemLocal is {} systemIp&&systemIp!=Local){packet=packet.ToArray();MobileIpv4Translation.Rewrite(packet,16,systemIp);}
            lock(owner.writeGate)return Volatile.Read(ref stopped)==0&&!owner.stop.IsCancellationRequested&&owner.tun.Write(packet);
        }
        public void Stop(){if(Interlocked.Exchange(ref stopped,1)==0){incoming.CompleteAdding();while(incoming.TryTake(out _)){} }}
        public void Dispose()=>Stop();
    }
    public async ValueTask DisposeAsync()
    {
        if(Interlocked.Exchange(ref disposed,1)!=0)return;
        stop.Cancel();tun.Stop();
        try{await reading;}finally{foreach(var port in ports.Values)port.Dispose();tun.Dispose();stop.Dispose();}
    }
}
