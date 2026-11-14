using Android.Content;
using Android.Content.PM;
using Android.Net;
using System.Buffers.Binary;
using StreamLink.Core;

namespace ConWU.Android;

// Android needs no raw driver: UU packets addressed to an approved peer enter
// the existing VPN. The Windows peer must enable its verified binding gate.
// Attribute observations to UU's UID rather than labeling all VPN traffic UU.
sealed class AndroidUuTakeover(Context context)
{
    public const string Package="com.netease.uuremote";
    readonly object gate=new();
    readonly Dictionary<(byte Protocol,uint Local,int Port,uint Remote,int PeerPort),(long Until,bool Uu)> owners=new();
    readonly Dictionary<string,Counter> counts=new();
    sealed class Counter {public long Received,Sent,SampleBytes,SampleAt,Rate,Last;}
    public bool Installed {get {try{return context.PackageManager!.GetApplicationInfo(Package,0)!=null;}catch(PackageManager.NameNotFoundException){return false;}}}
    public void Observe(string network,ReadOnlyMemory<byte> memory,bool received)
    {
        if(!OperatingSystem.IsAndroidVersionAtLeast(29))return;
        try{lock(gate){
            var p=memory.Span;int header=(p[0]&15)*4;
            if(p.Length<header+4||p[9] is not(6 or 17)||(BinaryPrimitives.ReadUInt16BigEndian(p[6..])&0x1fff)!=0)return;
            uint source=BinaryPrimitives.ReadUInt32BigEndian(p[12..]),target=BinaryPrimitives.ReadUInt32BigEndian(p[16..]);
            int from=BinaryPrimitives.ReadUInt16BigEndian(p[header..]),to=BinaryPrimitives.ReadUInt16BigEndian(p[(header+2)..]);
            uint local=received?target:source,remote=received?source:target;int localPort=received?to:from,remotePort=received?from:to;
            var key=(p[9],local,localPort,remote,remotePort);long now=Environment.TickCount64;
            if(!owners.TryGetValue(key,out var known)||now>=known.Until){
                if(owners.Count>=256)owners.Clear();
                var manager=(ConnectivityManager)context.GetSystemService(Context.ConnectivityService)!;
                static string Ip(uint value){Span<byte> bytes=stackalloc byte[4];BinaryPrimitives.WriteUInt32BigEndian(bytes,value);return new System.Net.IPAddress(bytes).ToString();}
                using var localAddress=new Java.Net.InetSocketAddress(Ip(local),localPort);using var remoteAddress=new Java.Net.InetSocketAddress(Ip(remote),remotePort);
                int uid=manager.GetConnectionOwnerUid(p[9],localAddress,remoteAddress);
                int expected=context.PackageManager!.GetApplicationInfo(Package,0)!.Uid;
                known=(now+3000,uid>=0&&uid==expected);owners[key]=known;
            }
            if(!known.Uu)return;
            if(!counts.TryGetValue(network,out var count))counts[network]=count=new(){SampleAt=now};
            if(received)count.Received+=p.Length;else count.Sent+=p.Length;
            count.Last=now;long elapsed=now-count.SampleAt;
            if(elapsed>=1000){count.Rate=(count.Received+count.Sent-count.SampleBytes)*1000/elapsed;count.SampleBytes=count.Received+count.Sent;count.SampleAt=now;}
        }}catch(Exception ex)when(ex is Java.Lang.RuntimeException or PackageManager.NameNotFoundException or InvalidOperationException){/* Observation must never break the VPN. */}
    }
    public UuTakeoverNetworkStatus[] Snapshot(MobileRuntime runtime)
    {
        lock(gate){long now=Environment.TickCount64;return runtime.Networks.Select(n=>{
            counts.TryGetValue(n.Id,out var c);long rate=c!=null&&now-c.Last<3000?c.Rate:0;
            return new UuTakeoverNetworkStatus(n.Id,n.Name,n.Mesh.LocalIp,runtime.State.UuTakeoverEnabled&&runtime.Connections.GetValueOrDefault(n.Id)?.Connected==true&&rate>=16384,c?.Received??0,c?.Sent??0,rate);
        }).ToArray();}
    }
}
