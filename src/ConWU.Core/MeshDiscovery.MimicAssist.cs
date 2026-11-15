using System.Net;
using System.Net.Http.Json;

namespace StreamLink.Core;

public sealed partial class MeshDiscoveryClient:IMimicAssistDiscovery
{
    bool mimicAssistUnavailable;
    readonly string mimicAssistService,mimicAssistPin;
    HttpClient? mimicAssistHttp;
    public Task<MimicAssistState> AssistMimic(string endpoint,CancellationToken token)=>AssistTcp(endpoint,"mimic",true,token);
    public async Task<MimicAssistState> AssistTcp(string endpoint,string mode,bool ready,CancellationToken token)
    {
        if(mimicAssistUnavailable)throw new NotSupportedException("协调服务器尚未启用所选协议的协调辅助");
        var control=Volatile.Read(ref mimicAssistHttp);
        if(control==null){var opened=PunchAssistHttp.Create(mimicAssistService,mimicAssistPin);control=Interlocked.CompareExchange(ref mimicAssistHttp,opened,null)??opened;if(!ReferenceEquals(opened,control))opened.Dispose();}
        if(mode!=profile.Pair.Mode||!TransportModes.TcpAssistance(mode))throw new IOException("协同请求与当前网络协议不符");
        var request=PunchAssistProtocol.Create(profile,boot,endpoint,ready);
        using var message=new HttpRequestMessage(HttpMethod.Post,$"v3/mesh/{profile.Pair.Network}/tcp-assist"){Content=JsonContent.Create(request)};
        message.Headers.Authorization=new("Bearer",profile.Pair.Auth);
        using var response=await control.SendAsync(message,token);
        if(response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.MethodNotAllowed){mimicAssistUnavailable=true;throw new NotSupportedException("协调服务器尚未启用所选协议的协调辅助");}
        response.EnsureSuccessStatusCode();
        MimicAssistState state;
        try{state=await response.Content.ReadFromJsonAsync<MimicAssistState>(token)??throw new IOException("协同探测通知为空");}
        catch(System.Text.Json.JsonException error){throw new IOException("协同探测通知格式无效",error);}
        if(state.Version!=1||state.Mode!=mode||state.PeerEndpoint is not {Length:<=64}||state.StartAfterMilliseconds is < -30000 or >6000||state.Round!=Guid.Empty&&state.PeerEndpoint.Length==0)throw new IOException("协同探测通知无效");
        if(state.PeerEndpoint.Length>0){
            var candidate=PunchAssistProtocol.Candidate(state.PeerEndpoint);
            if(!control.BaseAddress!.IsLoopback&&!PortControlRoute.GlobalV4(candidate.Address))throw new IOException("公网协调辅助不能指示探测本机或私网地址");
        }
        return state;
    }
}
