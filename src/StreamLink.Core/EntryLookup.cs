using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

// Short codes locate a temporary, signed address advertisement. They do not
// authorize enrollment: the existing committed ECDH/SAS/approval still applies.
public sealed record EntryAdvertisement(string Network,int Slot,string Code,string HostCommitment,string[] Endpoints,long Expires,string Signature);
public sealed record EntryLookupRecord(string OwnerKey,MeshMember Host,EntryAdvertisement Entry);
public sealed record EntryLookupQuery(string Code);
public static class EntryLookup
{
    static byte[] Data(EntryAdvertisement a)=>JsonSerializer.SerializeToUtf8Bytes(new{domain="conwu-existing-entry-backup-v1",a.Network,a.Slot,a.Code,a.HostCommitment,a.Endpoints,a.Expires});
    public static bool ValidCode(string? code)=>code is {Length:6}&&code.All(char.IsAsciiDigit);
    public static EntryAdvertisement Sign(MeshProfile owner,PairRoomTicket ticket,string[] endpoints)
    {
        if(!owner.IsOwner||!owner.Pair.Direct)throw new IOException("只有直连网络主机可以发布备用入口");
        var a=new EntryAdvertisement(owner.Pair.Network,owner.Self.Slot,ticket.Code,ticket.HostCommitment,endpoints.Distinct().Take(8).ToArray(),ticket.Expires,"");
        return a with{Signature=MeshIdentity.Sign(owner.SigningPrivate,Data(a))};
    }
    public static void Validate(EntryLookupRecord record,string code,long? utc=null)
    {
        var a=record.Entry;long now=utc??DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if(!ValidCode(code)||a==null||a.Code!=code||a.Slot!=1||record.Host==null||record.Host.Slot!=1||!Guid.TryParseExact(a.Network,"N",out _)||MeshIdentity.NetworkId(record.OwnerKey)!=a.Network||
            !PairKeyExchange.ValidCommitment(a.HostCommitment)||a.Expires<=now||a.Expires>now+330||a.Endpoints is not {Length:>0 and <=8}||a.Endpoints.Distinct().Count()!=a.Endpoints.Length||
            a.Endpoints.Any(e=>!IPEndPoint.TryParse(e,out var ep)||ep.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork||ep.Port==0||!ExistingEntryResolver.EndpointAddress(ep.Address)))
            throw new CryptographicException("备用协调返回的入口公告无效或已过期");
        MeshIdentity.ValidateMember(a.Network,record.OwnerKey,record.Host);
        if(!MeshIdentity.Verify(record.Host.SigningKey,Data(a),a.Signature))throw new CryptographicException("备用入口签名不匹配");
    }
}
public sealed class EntryLookupClient:IDisposable
{
    readonly HttpClient http;
    public EntryLookupClient(string service,string pin)
    {
        Pairing.Create(service,pin).Validate();
        var handler=new HttpClientHandler{UseProxy=false,AllowAutoRedirect=false};
        if(pin.Length>0)handler.ServerCertificateCustomValidationCallback=(_,cert,_,_)=>cert!=null&&DateTime.UtcNow>=cert.NotBefore.ToUniversalTime()&&DateTime.UtcNow<=cert.NotAfter.ToUniversalTime()&&CryptographicOperations.FixedTimeEquals(SHA256.HashData(cert.RawData),Convert.FromHexString(pin));
        http=new(handler){BaseAddress=new(service),Timeout=TimeSpan.FromSeconds(5),MaxResponseContentBufferSize=32768};
    }
    public async Task Publish(MeshProfile owner,EntryAdvertisement entry,CancellationToken token)
    {
        // Register the owner-signed directory under the network capability;
        // neither the directory signing key nor the pairing ECDH key is sent.
        using var directory=new HttpRequestMessage(HttpMethod.Put,$"v3/mesh/{owner.Pair.Network}/directory"){Content=JsonContent.Create(owner.Directory)};
        directory.Headers.Authorization=new("Bearer",owner.Pair.Auth);
        using(var result=await http.SendAsync(directory,token))result.EnsureSuccessStatusCode();
        using var publish=new HttpRequestMessage(HttpMethod.Put,$"v3/mesh/{owner.Pair.Network}/entry"){Content=JsonContent.Create(entry)};
        publish.Headers.Authorization=new("Bearer",owner.Pair.Auth);
        using var response=await http.SendAsync(publish,token);response.EnsureSuccessStatusCode();
    }
    public async Task<EntryLookupRecord?> Find(string code,CancellationToken token)
    {
        if(!EntryLookup.ValidCode(code))throw new FormatException("请输入六位数字配对码");
        using var response=await http.PostAsJsonAsync("v3/entry-lookup",new EntryLookupQuery(code),token);
        if(response.StatusCode==HttpStatusCode.NotFound)return null;
        response.EnsureSuccessStatusCode();
        var found=await response.Content.ReadFromJsonAsync<EntryLookupRecord>(token)??throw new IOException("备用协调返回了空入口公告");
        EntryLookup.Validate(found,code);return found;
    }
    public void Dispose()=>http.Dispose();
}
