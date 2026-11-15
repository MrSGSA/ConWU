using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace StreamLink.Core;

// Assistance carries only fresh candidate hints and scheduling. It never
// carries enrollment, authorizes a member, or forwards business datagrams.
public sealed record PunchAssistCreate(string Endpoint,string HostRoom,string Commitment,string Mode="mimic",bool Ready=true);
public sealed record PunchAssistJoin(string Code,string RequestId,string Commitment,string Mode="mimic");
public sealed record PunchAssistUpdate(string Token,string Endpoint="",bool Close=false,bool Ready=true);
public sealed record PunchAssistState(string Room,string Token,long Expires,string HostRoom,string Commitment,
    string HostEndpoint,string GuestEndpoint,Guid Round,int StartAfterMilliseconds,string Mode="mimic");
public sealed record PunchAssistStatus(int Waiting,int Scheduled,long TotalScheduled);
public sealed record MimicAssistRequest(int Version,Guid RequestId,Guid Boot,int Slot,string Device,long Issued,string Endpoint,string Signature)
{public string Mode{get;init;}="mimic";public bool Ready{get;init;}=true;}
public sealed record MimicAssistState(int Version,string PeerEndpoint,Guid Round,int StartAfterMilliseconds,string Mode="mimic");
public interface ITcpAssistDiscovery
{
    Task<MimicAssistState> AssistTcp(string endpoint,string mode,bool ready,CancellationToken token);
}
public interface IMimicAssistDiscovery:ITcpAssistDiscovery
{
    Task<MimicAssistState> AssistMimic(string endpoint,CancellationToken token);
    Task<MimicAssistState> ITcpAssistDiscovery.AssistTcp(string endpoint,string mode,bool ready,CancellationToken token)
        =>mode=="mimic"?AssistMimic(endpoint,token):throw new NotSupportedException("旧协同接口不支持此协议");
}
public static class PunchAssistProtocol
{
    public const int Version=1,MaximumSessions=128,InvitationSeconds=300,StartDelayMs=1000,MemberStartDelayMs=5000;
    public static bool Code(string value)=>value is {Length:6}&&value.All(char.IsAsciiDigit);
    public static bool Secret(string value)=>value is {Length:64}&&value.All(char.IsAsciiHexDigit);
    public static IPEndPoint Candidate(string value)
    {
        if(value is not {Length:>=3 and <=64}||!IPEndPoint.TryParse(value,out var ep)||ep.AddressFamily!=AddressFamily.InterNetwork||ep.Port==0||
            !(PortControlRoute.GlobalV4(ep.Address)||IPAddress.IsLoopback(ep.Address)))throw new FormatException("协同探测候选必须为有效公网 IPv4 地址");
        return ep;
    }
    public static bool MatchesSource(string endpoint,IPAddress source)
    {
        if(source.IsIPv4MappedToIPv6)source=source.MapToIPv4();
        var candidate=Candidate(endpoint);
        return candidate.Address.Equals(source)&&(PortControlRoute.GlobalV4(source)||IPAddress.IsLoopback(source));
    }
    static byte[] Signed(string network,MimicAssistRequest r)=>System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new{
        domain="conwu-tcp-assist-v2",network,r.Version,r.RequestId,r.Boot,r.Slot,r.Device,r.Issued,r.Endpoint,r.Mode,r.Ready});
    public static MimicAssistRequest Create(MeshProfile mesh,Guid boot,string endpoint,bool ready=true)
    {
        _=Candidate(endpoint);
        var r=new MimicAssistRequest(Version,Guid.NewGuid(),boot,mesh.Self.Slot,mesh.Self.Device,DateTimeOffset.UtcNow.ToUnixTimeSeconds(),endpoint,""){Mode=mesh.Pair.Mode,Ready=ready};
        return r with{Signature=MeshIdentity.Sign(mesh.SigningPrivate,Signed(mesh.Pair.Network,r))};
    }
    public static void Verify(string network,MeshMember member,MimicAssistRequest r)
    {
        if(r.Version!=Version||!TransportModes.TcpAssistance(r.Mode)||r.RequestId==Guid.Empty||r.Boot==Guid.Empty||r.Slot!=member.Slot||r.Device!=member.Device||
            Math.Abs((decimal)r.Issued-DateTimeOffset.UtcNow.ToUnixTimeSeconds())>30||r.Signature is not {Length:>0 and <=256})throw new FormatException("协同探测请求无效或过期");
        _=Candidate(r.Endpoint);
        if(!MeshIdentity.Verify(member.SigningKey,Signed(network,r),r.Signature))throw new CryptographicException("协同探测身份签名无效");
    }
    public static string? StunServer(DeviceProfile profile)
    {
        if(profile.UsesExistingEntriesOnly||!TransportModes.TcpAssistance(profile.TransportMode)||profile.CoordinationService.Length==0)return null;
        var uri=new Uri(profile.CoordinationService);
        // TCP STUN uses the actual listener, not an HTTP reverse-proxy route.
        return uri.AbsolutePath=="/"?uri.Host+":"+uri.Port:null;
    }
}

public sealed class PunchAssistClient:IDisposable
{
    readonly HttpClient http;
    readonly Func<CancellationToken,Task<IPEndPoint>>? resolve;
    public PunchAssistClient(string service,string pin="",bool bootstrap=false)
    {
        // The compact code carries no full TLS pin. Bootstrap is only an
        // untrusted hint channel; the direct SAS exchange grants membership.
        http=PunchAssistHttp.Create(service,pin,bootstrap);
    }
    internal PunchAssistClient(HttpClient http,Func<CancellationToken,Task<IPEndPoint>>? resolve=null){this.http=http;this.resolve=resolve;}
    public Task<IPEndPoint> ResolveEndpoint(CancellationToken token)=>resolve?.Invoke(token)??Stun.Resolve(http.BaseAddress!.Host+":"+http.BaseAddress.Port,token);
    public async Task RequireSupport(CancellationToken token,string mode="mimic")
    {
        using var reply=await http.GetAsync("health",token);reply.EnsureSuccessStatusCode();
        try{
            using var health=JsonDocument.Parse(await reply.Content.ReadAsStringAsync(token));
            if(!health.RootElement.TryGetProperty("punchAssist",out var version)||version.GetInt32()!=1||
                !health.RootElement.TryGetProperty("punchTcpStun",out var stun)||stun.GetInt32()!=1)throw new IOException("协调服务器尚不支持直接监听上的首次协同打洞，请升级协调端");
            if(mode!="mimic"&&(!health.RootElement.TryGetProperty("punchModes",out var modes)||!modes.EnumerateArray().Any(value=>value.GetString()==mode)))throw new IOException("协调服务器尚未支持所选协议的协同打洞");
        }catch(Exception error)when(error is JsonException or InvalidOperationException or FormatException){throw new IOException("协调辅助能力响应无效",error);}
    }
    async Task<PunchAssistState> Post<T>(string path,T value,CancellationToken token)
    {
        using var response=await http.PostAsJsonAsync("v1/punch-assist/"+path,value,token);
        if(response.StatusCode==HttpStatusCode.Conflict)throw new IOException("协同打洞会话已变化、被占用或候选与观察来源不符，请重新生成直连码");
        response.EnsureSuccessStatusCode();
        PunchAssistState state;
        try{state=await response.Content.ReadFromJsonAsync<PunchAssistState>(token)??throw new IOException("协同打洞响应为空");}
        catch(JsonException error){throw new IOException("协同打洞响应格式无效",error);}
        if(!PunchAssistProtocol.Code(state.Room)||!PunchAssistProtocol.Secret(state.Token)||!PunchAssistProtocol.Code(state.HostRoom)||!PairKeyExchange.ValidCommitment(state.Commitment)||state.GuestEndpoint is not {Length:<=64}||
            state.Expires<=DateTimeOffset.UtcNow.ToUnixTimeSeconds()||state.Expires>DateTimeOffset.UtcNow.AddSeconds(305).ToUnixTimeSeconds()||state.StartAfterMilliseconds is < -30000 or >2000)throw new IOException("协同打洞响应无效");
        var host=PunchAssistProtocol.Candidate(state.HostEndpoint);
        var guest=state.GuestEndpoint.Length>0?PunchAssistProtocol.Candidate(state.GuestEndpoint):null;
        if(!http.BaseAddress!.IsLoopback&&(!PortControlRoute.GlobalV4(host.Address)||guest!=null&&!PortControlRoute.GlobalV4(guest.Address)))throw new IOException("公网辅助节点不能指示探测本机或私网地址");
        return state;
    }
    public async Task<PunchAssistState> Create(PunchAssistCreate request,CancellationToken token)
    {var state=await Post("create",request,token);if(state.Mode!=request.Mode)throw new IOException("辅助会话的传输协议不符");return state;}
    public async Task<PunchAssistState> Join(PunchAssistJoin request,CancellationToken token)
    {var state=await Post("join",request,token);if(state.Mode!=request.Mode)throw new IOException("辅助会话的传输协议不符");return state;}
    public async Task<PunchAssistState> Update(PunchAssistState state,string endpoint,CancellationToken token,bool ready=true)
    {
        var next=await Post(state.Room,new PunchAssistUpdate(state.Token,endpoint,Ready:ready),token);
        if(next.Room!=state.Room||next.Token!=state.Token||next.Expires!=state.Expires||next.HostRoom!=state.HostRoom||next.Commitment!=state.Commitment||next.HostEndpoint!=state.HostEndpoint||
            next.Mode!=state.Mode||state.Round!=Guid.Empty&&next.Round!=state.Round)throw new IOException("协同打洞会话绑定已改变，请重新生成直连码");
        return next;
    }
    public async Task Close(PunchAssistState state,CancellationToken token)
    {using var response=await http.PostAsJsonAsync("v1/punch-assist/"+state.Room,new PunchAssistUpdate(state.Token,Close:true),token);response.EnsureSuccessStatusCode();}
    public async Task<PunchAssistState> Wait(PunchAssistState state,string endpoint,CancellationToken token,Func<IPEndPoint,CancellationToken,Task>? prepare=null,bool owner=false)
    {
        bool prepared=prepare==null;
        while(true){
            long began=Stopwatch.GetTimestamp();state=await Update(state,endpoint,token,prepared);
            string peer=owner?state.GuestEndpoint:state.HostEndpoint;
            if(!prepared&&peer.Length>0){await prepare!(PunchAssistProtocol.Candidate(peer),token);prepared=true;continue;}
            if(state.Round!=Guid.Empty){
                int left=state.StartAfterMilliseconds-(int)(Stopwatch.GetElapsedTime(began).TotalMilliseconds/2);
                if(left< -2000)throw new IOException("本轮协同探测时序已过期，请重新生成直连码");
                if(left>0)await Task.Delay(left,token);return state;
            }
            await Task.Delay(250,token);
        }
    }
    public void Dispose()=>http.Dispose();
}
