using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

public static class MeshCoordinatorPreflight
{
    public static async Task Check(Pairing pair,CancellationToken token)
    {
        pair.Validate();
        using var handler=new HttpClientHandler{UseProxy=false,AllowAutoRedirect=false};
        if(pair.CertificatePin.Length>0)handler.ServerCertificateCustomValidationCallback=(_,cert,_,_)=>cert!=null&&
            DateTime.UtcNow>=cert.NotBefore.ToUniversalTime()&&DateTime.UtcNow<=cert.NotAfter.ToUniversalTime()&&
            CryptographicOperations.FixedTimeEquals(SHA256.HashData(cert.RawData),Convert.FromHexString(pair.CertificatePin));
        using var http=new HttpClient(handler){BaseAddress=new(pair.Service),Timeout=TimeSpan.FromSeconds(8),MaxResponseContentBufferSize=16384};
        using var reply=await http.GetAsync("health",token);reply.EnsureSuccessStatusCode();
        using var health=await reply.Content.ReadFromJsonAsync<JsonDocument>(token)??throw new IOException("协调服务状态为空");
        var h=health.RootElement;
        if(!h.TryGetProperty("meshProtocol",out var mesh)||mesh.GetInt32()!=4||!h.TryGetProperty("meshTraversal",out var traversal)||traversal.GetInt32()!=MeshTraversal.Version||
            !h.TryGetProperty("relay",out var relay)||relay.ValueKind!=JsonValueKind.False)
            throw new IOException("协调服务未声明 Mesh v4 与新版打洞能力；请使用配套个人协调服务，原日用协调无需替换");
    }
}
