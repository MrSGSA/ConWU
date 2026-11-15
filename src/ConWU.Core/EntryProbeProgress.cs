using System.Diagnostics;
using System.Net.Sockets;

namespace StreamLink.Core;

public sealed record EntryProbeProgress(string Stage,string Detail);

public sealed class EntryProbeException(string stage,string reason,string message,Exception inner):IOException(message,inner)
{
    public string Stage {get;}=stage;
    public string Reason {get;}=reason;
}

// One preparation round owns its cancellation and cleanup. A STUN observation
// is still a candidate; this wrapper never turns it into reachability proof.
public static class HostEntryProbe
{
    public static Task<IMapping> Create(DeviceProfile profile,Action<string> log,Action<EntryProbeProgress> progress,CancellationToken token)
        => Run((report,ct)=>PunchAssistProtocol.StunServer(profile)!=null
            ?Coordinated(profile,log,report,ct):profile.TransportMode=="mimic"&&OperatingSystem.IsWindows()
            ?Mimic(profile,log,report,ct):profile.TransportMode=="udp"
            ?Udp(profile,log,report,ct)
            :TransportModes.Stream(profile.TransportMode)
                ?StreamMapping.Create(profile.ListenPort,log,ct,profile.OrderedTcp(),profile.PortControlMapping,profile.SourcePort,profile.ResourceScope,report)
                :GatewayMapping.CreateTcp(profile.SourcePort,profile.ListenPort,log,ct,profile.OrderedTcp(),profile.ResourceScope,profile.PortControlMapping,report),
            log,progress,token,TimeSpan.FromSeconds(30));

    static async Task<IMapping> Coordinated(DeviceProfile profile,Action<string> log,Action<EntryProbeProgress> progress,CancellationToken token)
    {
        string[] servers=new[]{PunchAssistProtocol.StunServer(profile)!}.Concat(profile.OrderedTcp()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        progress(new("ReceiverStun","从所选协议的实际源端口观察候选，准备协调探测"));
        return profile.TransportMode=="faketcp"?await FakeTcpSourceMapping.Create(profile.ListenPort,servers,log,token)
            :await MimicMapping.Create(profile.ListenPort,log,token,servers,progress,mode:profile.TransportMode);
    }

    static async Task<IMapping> Mimic(DeviceProfile profile,Action<string> log,Action<EntryProbeProgress> progress,CancellationToken token)
        =>await MimicMapping.Create(profile.ListenPort,log,token,PunchAssistProtocol.StunServer(profile) is {} helper
            ?new[]{helper}.Concat(profile.OrderedTcp()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray():profile.OrderedTcp(),progress);

    static async Task<IMapping> Udp(DeviceProfile profile,Action<string> log,Action<EntryProbeProgress> progress,CancellationToken token)
    {
        progress(new("StunQuery","正在查询 UDP STUN 并准备网关映射"));
        return await UdpMapping.Create(profile.ListenPort,profile.ListenPort,log,token,profile.UdpStun,profile.ResourceScope);
    }

    internal static async Task<IMapping> Run(Func<Action<EntryProbeProgress>,CancellationToken,Task<IMapping>> prepare,
        Action<string> log,Action<EntryProbeProgress> progress,CancellationToken token,TimeSpan budget)
    {
        var clock=Stopwatch.StartNew();var last=new EntryProbeProgress("Starting","正在准备本机公网入口");
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(token);stop.CancelAfter(budget);
        void Report(EntryProbeProgress next){last=next;progress(next);log($"主机入口 stage={next.Stage} elapsedMs={clock.ElapsedMilliseconds}：{next.Detail}");}
        IMapping? opening=null;
        try{
            token.ThrowIfCancellationRequested();Report(last);
            opening=await prepare(Report,stop.Token);
            stop.Token.ThrowIfCancellationRequested();
            if(!opening.IsValid)throw new IOException("入口在准备完成前已经失效");
            var result=opening;opening=null;return result;
        }catch(Exception error)when(!token.IsCancellationRequested&&error is IOException or SocketException or HttpRequestException or OperationCanceledException or TimeoutException){
            string reason=stop.IsCancellationRequested||error is TimeoutException?"Timeout":error is SocketException socket?socket.SocketErrorCode.ToString():"Unavailable";
            string detail=reason=="Timeout"?$"本轮入口准备超过 {budget.TotalSeconds:0} 秒预算，停在：{last.Detail}":$"{last.Detail}未完成：{error.Message}";
            throw new EntryProbeException(last.Stage,reason,detail,error);
        }finally{
            if(opening!=null)await opening.DisposeAsync();
        }
    }
}
