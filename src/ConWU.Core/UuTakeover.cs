using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

// Device-local preference. Never part of an invitation or approved peer settings.
[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public sealed record UuTakeoverSettings(bool Enabled=false,string NetworkId="")
{
    // Retained for reading the earlier local test preference. Selection is now
    // automatic: this legacy field never limits participating networks.
    public void Validate(){if(NetworkId is null||NetworkId.Length>0&&!Guid.TryParseExact(NetworkId,"N",out _))throw new FormatException("请选择有效的 UU 接管网络");}
    public string Revision()=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(this))).ToLowerInvariant()[..24];
}
public sealed record UuTakeoverAction(UuTakeoverSettings Settings,string ExpectedRevision);
public sealed record UuTakeoverStatus(bool Supported,UuTakeoverSettings Settings,string Revision,string State,string Message)
{
    public bool RulesActive {get;init;}
    public bool TrafficObserved {get;init;}
    public string NetworkId {get;init;}="";
    public string NetworkName {get;init;}="";
    public string VirtualIp {get;init;}="";
    public int[] ProcessIds {get;init;}=[];
    public long ReceivedBytes {get;init;}
    public long SentBytes {get;init;}
    public long RecentBytesPerSecond {get;init;}
    public long LastTrafficAt {get;init;}
    public long RestrictedBindings {get;init;}
    public bool ReconnectRecommended {get;init;}
    public UuTakeoverNetworkStatus[] Networks {get;init;}=[];
    public static UuTakeoverStatus Idle(UuTakeoverSettings settings)=>new(OperatingSystem.IsWindows(),settings,settings.Revision(),
        settings.Enabled?"WaitingNetwork":"Disabled",settings.Enabled?"等待可用的 ConWU 网络":"未开启 UU 远程通道接管");
}
public sealed record UuTakeoverNetwork(string Id,string Name,string VirtualIp,string[] PeerVirtualIps,bool Ready);
public sealed record UuTakeoverNetworkStatus(string Id,string Name,string VirtualIp,bool TrafficObserved=false,long ReceivedBytes=0,long SentBytes=0,long RecentBytesPerSecond=0);
public sealed record UuTakeoverProcess(int Id,long StartedAt,string Image);
public sealed record UuTakeoverTraffic(long ReceivedBytes=0,long SentBytes=0,long RecentBytesPerSecond=0,
    bool Sustained=false,long LastTrafficAt=0,long RestrictedBindings=0,string Error="")
{
    public UuTakeoverNetworkStatus[] Networks {get;init;}=[];
}
public interface IUuTakeoverGate:IDisposable
{
    UuTakeoverTraffic Observe(DateTimeOffset now);
}
public interface IUuTakeoverPlatform
{
    bool Supported {get;}
    UuTakeoverProcess[] Processes();
    IUuTakeoverGate Open(IReadOnlyList<UuTakeoverNetwork> networks,UuTakeoverProcess[] processes);
}

// The service calls Refresh on a dedicated worker. No driver or process query
// runs on a UI/status request, and a disabled preference opens no resources.
public sealed class UuTakeoverController(IUuTakeoverPlatform platform):IDisposable
{
    IUuTakeoverGate? gate;
    string key="";
    UuTakeoverStatus status=UuTakeoverStatus.Idle(new());
    DateTimeOffset retryAt;
    bool disposed;
    readonly object lifecycle=new();
    public UuTakeoverStatus Status=>Volatile.Read(ref status);
    public void Refresh(UuTakeoverSettings settings,IReadOnlyList<UuTakeoverNetwork> networks,DateTimeOffset now)
    {lock(lifecycle)RefreshCore(settings,networks,now);}
    void RefreshCore(UuTakeoverSettings settings,IReadOnlyList<UuTakeoverNetwork> networks,DateTimeOffset now)
    {
        if(disposed)return;
        var next=new UuTakeoverStatus(platform.Supported,settings,settings.Revision(),"Disabled","未开启 UU 远程通道接管");
        void Publish(string state,string message,bool close=true){if(close)Close();Volatile.Write(ref status,next with{State=state,Message=message});}
        if(!settings.Enabled){retryAt=default;Publish("Disabled","未开启 UU 远程通道接管");return;}
        if(!platform.Supported){Publish("Unsupported","本机暂不支持 UU 通道接管；Android 可通过已连接的 ConWU VPN 访问主机");return;}
        var candidates=networks.Where(n=>n.Ready&&ValidNetwork(n)).DistinctBy(n=>n.Id).OrderBy(n=>n.Id,StringComparer.Ordinal).ToArray();
        if(candidates.Length==0){Publish("WaitingNetwork","等待 ConWU 建立直连；当前未限制 UU");return;}
        next=next with{NetworkId=candidates.Length==1?candidates[0].Id:"",NetworkName=candidates.Length==1?candidates[0].Name:$"{candidates.Length} 条已直连网络",
            VirtualIp=candidates.Length==1?candidates[0].VirtualIp:"",Networks=candidates.Select(n=>new UuTakeoverNetworkStatus(n.Id,n.Name,n.VirtualIp)).ToArray()};
        try{
            var processes=platform.Processes().OrderBy(p=>p.Id).ToArray();next=next with{ProcessIds=processes.Select(p=>p.Id).ToArray()};
            if(processes.Length==0){retryAt=default;Publish("WaitingUu","等待 UU 远程启动；当前未限制其他程序");return;}
            string desired=string.Join('|',candidates.Select(n=>n.Id+"/"+n.VirtualIp+"/"+string.Join(',',n.PeerVirtualIps.Order())))+"/"+string.Join(',',processes.Select(p=>$"{p.Id}:{p.StartedAt}"));
            if(key!=desired){
                Close();
                if(now<retryAt){Publish("Error",Status.Message);return;}
                gate=platform.Open(candidates,processes);key=desired;retryAt=default;
            }
            var traffic=gate!.Observe(now);
            if(traffic.Error.Length>0)throw new IOException(traffic.Error);
            Volatile.Write(ref status,next with{State=traffic.Sustained?"Transmitting":traffic.LastTrafficAt>0?"Idle":"Ready",
                Message=traffic.Sustained?"已检测到 UU 持续流量经过 ConWU":traffic.LastTrafficAt>0?"已检测到 UU 数据，当前流量较少或会话空闲":"接管已就绪；请新建或重新连接 UU 会话",
                RulesActive=true,TrafficObserved=traffic.Sustained,ReconnectRecommended=traffic.LastTrafficAt==0,
                ReceivedBytes=traffic.ReceivedBytes,SentBytes=traffic.SentBytes,RecentBytesPerSecond=traffic.RecentBytesPerSecond,
                LastTrafficAt=traffic.LastTrafficAt,RestrictedBindings=traffic.RestrictedBindings,
                Networks=traffic.Networks.Length>0?traffic.Networks:next.Networks});
        }catch(Exception ex){
            retryAt=now.AddSeconds(5);Publish("Error","接管暂不可用，已撤下临时限制："+ex.Message);
        }
    }
    static bool ValidNetwork(UuTakeoverNetwork network)
    {
        if(!IPAddress.TryParse(network.VirtualIp,out var local)||local.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork||IPAddress.IsLoopback(local))return false;
        byte[] bytes=local.GetAddressBytes();if(bytes[0] is 0 or >=224||bytes[3] is 0 or 255||network.PeerVirtualIps.Length==0)return false;
        return network.PeerVirtualIps.All(value=>IPAddress.TryParse(value,out var peer)&&peer.AddressFamily==local.AddressFamily&&
            peer.GetAddressBytes().AsSpan(0,3).SequenceEqual(bytes.AsSpan(0,3))&&!peer.Equals(local)&&peer.GetAddressBytes()[3] is >0 and <255);
    }
    void Close(){var previous=gate;gate=null;key="";previous?.Dispose();}
    public void Dispose(){lock(lifecycle){if(disposed)return;disposed=true;Close();Volatile.Write(ref status,status with{RulesActive=false,TrafficObserved=false,State="Stopped",Message="接管已停止，临时限制已撤下"});}}
}
