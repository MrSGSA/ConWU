using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace StreamLink.Core;

public sealed record PkarrAnnouncement(int Version,string Mode,long Expires,string[] Endpoints);
public sealed record PkarrRecord(long Sequence,PkarrAnnouncement Announcement,byte[] Packet);
public sealed record PkarrStatus(bool Enabled,string State,string Source="",long PublishedAt=0,string Error=""){public string[] Endpoints {get;init;}=[];}

// PKARR HTTP gateways carry discovery records only. The payload is a real
// BEP44-signed DNS TXT answer; no member credentials or network secrets occur.
public static class PkarrPacket
{
    const string Alphabet="ybndrfg8ejkmcpqxot1uwisza345h769";
    public static string NewSeed()=>Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    public static string PublicKey(string seed)=>EncodeKey(new Ed25519PrivateKeyParameters(Convert.FromBase64String(seed),0).GeneratePublicKey().GetEncoded());
    public static string Source(string seed)=>"pkarr://"+PublicKey(seed);
    public static string EncodeKey(ReadOnlySpan<byte> key)
    {
        if(key.Length!=32)throw new FormatException("PKARR 公钥应为 32 字节");
        var output=new StringBuilder(52);uint acc=0;int bits=0;
        foreach(byte b in key){acc=(acc<<8)|b;bits+=8;while(bits>=5){bits-=5;output.Append(Alphabet[(int)((acc>>bits)&31)]);}}
        if(bits>0)output.Append(Alphabet[(int)((acc<<(5-bits))&31)]);return output.ToString();
    }
    public static byte[] DecodeKey(string key)
    {
        if(key is not {Length:52})throw new FormatException("PKARR 地址需要完整的 52 位公钥");
        byte[] result=new byte[32];uint acc=0;int bits=0,index=0;
        foreach(char c in key){int value=Alphabet.IndexOf(c);if(value<0)throw new FormatException("PKARR 公钥编码无效");acc=(acc<<5)|(uint)value;bits+=5;if(bits>=8){bits-=8;if(index>=32)throw new FormatException("PKARR 公钥过长");result[index++]=(byte)(acc>>bits);}}
        if(index!=32||EncodeKey(result)!=key)throw new FormatException("PKARR 公钥编码不规范");return result;
    }
    public static string KeyFromSource(string source)
    {
        if(!source.StartsWith("pkarr://",StringComparison.Ordinal)||source.Length!=60)throw new FormatException("PKARR 入口格式为 pkarr://完整公钥");
        string key=source[8..];DecodeKey(key);return key;
    }
    static byte[] Signable(long sequence,ReadOnlySpan<byte> dns)=>Encoding.ASCII.GetBytes($"3:seqi{sequence.ToString(CultureInfo.InvariantCulture)}e1:v{dns.Length.ToString(CultureInfo.InvariantCulture)}:").Concat(dns.ToArray()).ToArray();
    public static byte[] Create(string seed,long sequence,PkarrAnnouncement announcement)
    {
        Validate(announcement,sequence,DateTimeOffset.FromUnixTimeMilliseconds(sequence/1000));
        byte[] text=JsonSerializer.SerializeToUtf8Bytes(announcement);var body=new List<byte>();
        for(int offset=0;offset<text.Length;offset+=255){int take=Math.Min(255,text.Length-offset);body.Add((byte)take);body.AddRange(text.AsSpan(offset,take).ToArray());}
        string key=PublicKey(seed);var dns=new List<byte>([0,0,0x84,0,0,0,0,1,0,0,0,0]);
        foreach(string label in new[]{"_conwu",key}){dns.Add((byte)label.Length);dns.AddRange(Encoding.ASCII.GetBytes(label));}dns.Add(0);
        dns.AddRange([0,16,0,1,0,0,1,44,(byte)(body.Count>>8),(byte)body.Count]);dns.AddRange(body);
        if(dns.Count>1000)throw new FormatException("PKARR 公告超过 1000 字节，请减少入口");
        byte[] wire=new byte[72+dns.Count],data=dns.ToArray();var signer=new Ed25519Signer();signer.Init(true,new Ed25519PrivateKeyParameters(Convert.FromBase64String(seed),0));byte[] signable=Signable(sequence,data);signer.BlockUpdate(signable,0,signable.Length);signer.GenerateSignature().CopyTo(wire,0);BinaryPrimitives.WriteInt64BigEndian(wire.AsSpan(64,8),sequence);data.CopyTo(wire,72);return wire;
    }
    public static PkarrRecord Read(string key,ReadOnlySpan<byte> wire,DateTimeOffset now)
    {
        if(wire.Length is <84 or >1072)throw new FormatException("PKARR 公告长度无效");byte[] publicKey=DecodeKey(key);long sequence=BinaryPrimitives.ReadInt64BigEndian(wire.Slice(64,8));
        if(sequence<=0||sequence/1000>now.AddMinutes(5).ToUnixTimeMilliseconds())throw new FormatException("PKARR 公告时间无效");
        byte[] dns=wire[72..].ToArray(),signable=Signable(sequence,dns);var verifier=new Ed25519Signer();verifier.Init(false,new Ed25519PublicKeyParameters(publicKey,0));verifier.BlockUpdate(signable,0,signable.Length);if(!verifier.VerifySignature(wire[..64].ToArray()))throw new CryptographicException("PKARR 公告签名无效");
        if(dns.Length<12||(dns[2]&0x82)!=0x80||BinaryPrimitives.ReadUInt16BigEndian(dns.AsSpan(4,2))!=0)throw new FormatException("PKARR DNS 应答无效");
        int count=BinaryPrimitives.ReadUInt16BigEndian(dns.AsSpan(6,2)),offset=12;if(count is <1 or >32)throw new FormatException("PKARR DNS 记录数量无效");PkarrAnnouncement? result=null;
        for(int i=0;i<count;i++){
            string name=ReadName(dns,ref offset);if(offset+10>dns.Length)throw new FormatException("PKARR DNS 记录截断");
            int type=BinaryPrimitives.ReadUInt16BigEndian(dns.AsSpan(offset,2)),klass=BinaryPrimitives.ReadUInt16BigEndian(dns.AsSpan(offset+2,2)),length=BinaryPrimitives.ReadUInt16BigEndian(dns.AsSpan(offset+8,2));offset+=10;int end=offset+length;if(end>dns.Length)throw new FormatException("PKARR DNS 数据截断");
            if(type==16&&(klass&0x7fff)==1&&name=="_conwu."+key){if(result!=null)throw new FormatException("PKARR 包含重复公告");var txt=new List<byte>();while(offset<end){int take=dns[offset++];if(offset+take>end)throw new FormatException("PKARR TXT 数据截断");txt.AddRange(dns.AsSpan(offset,take).ToArray());offset+=take;}result=JsonSerializer.Deserialize<PkarrAnnouncement>(txt.ToArray())??throw new FormatException("PKARR 公告为空");}
            offset=end;
        }
        if(result==null)throw new FormatException("PKARR 没有 ConWU 公告");Validate(result,sequence,now);return new(sequence,result,wire.ToArray());
    }
    static string ReadName(byte[] data,ref int offset)
    {
        var labels=new List<string>();int pos=offset,steps=0;bool jumped=false;var seen=new HashSet<int>();
        while(true){if(pos>=data.Length||!seen.Add(pos)||++steps>128)throw new FormatException("PKARR DNS 名称无效");int n=data[pos++];if(n==0){if(!jumped)offset=pos;break;}if((n&0xc0)==0xc0){if(pos>=data.Length)throw new FormatException("PKARR DNS 指针截断");int target=((n&0x3f)<<8)|data[pos++];if(target>=data.Length)throw new FormatException("PKARR DNS 指针越界");if(!jumped)offset=pos;jumped=true;pos=target;continue;}if(n>63||pos+n>data.Length)throw new FormatException("PKARR DNS 标签无效");labels.Add(Encoding.ASCII.GetString(data,pos,n).ToLowerInvariant());pos+=n;if(labels.Sum(l=>l.Length+1)>255)throw new FormatException("PKARR DNS 名称过长");}return string.Join('.',labels);
    }
    static void Validate(PkarrAnnouncement value,long sequence,DateTimeOffset now)
    {
        if(value.Version!=1||value.Mode is not ("faketcp" or "udp")||value.Endpoints is not {Length:>0 and <=8}||value.Expires<=now.ToUnixTimeSeconds()||value.Expires>sequence/1_000_000+7200||sequence/1_000_000<now.AddHours(-2).ToUnixTimeSeconds())throw new FormatException("PKARR 公告已过期或格式无效");
        foreach(string endpoint in value.Endpoints)if(!IPEndPoint.TryParse(endpoint,out var address)||!ExistingEntryResolver.EndpointAddress(address.Address)||address.Port==0)throw new FormatException("PKARR 公告包含无效入口");
    }
}

public sealed class PkarrClient:IDisposable
{
    // Defaults from the upstream Rust PKARR client; callers can inject a local
    // gateway in protocol tests. Redirects never turn signed lookup into an
    // arbitrary URL fetch or forward a publication body elsewhere.
    public static readonly string[] DefaultGateways=["https://pkarr.pubky.app","https://pkarr.pubky.org"];
    readonly HttpClient http;readonly bool owned;readonly string[] gateways;
    static readonly object cacheGate=new();static readonly Dictionary<string,PkarrRecord> newest=new(StringComparer.Ordinal);
    public PkarrClient(HttpClient? http=null,string[]? gateways=null){owned=http==null;this.http=http??new(new SocketsHttpHandler{AllowAutoRedirect=false,ConnectTimeout=TimeSpan.FromSeconds(5)}){Timeout=TimeSpan.FromSeconds(8)};this.gateways=gateways??DefaultGateways;if(this.gateways.Length is <1 or >4)throw new ArgumentException("PKARR 网关数量无效");}
    public async Task<string[]> Resolve(string source,string mode,CancellationToken token)
    {
        string key=PkarrPacket.KeyFromSource(source);var reads=await Task.WhenAll(gateways.Select(async gateway=>{
            try{using var response=await http.GetAsync(gateway.TrimEnd('/')+"/"+key,HttpCompletionOption.ResponseHeadersRead,token);response.EnsureSuccessStatusCode();await using var stream=await response.Content.ReadAsStreamAsync(token);byte[] bytes=new byte[1073];int used=0,n;while(used<bytes.Length&&(n=await stream.ReadAsync(bytes.AsMemory(used),token))>0)used+=n;if(used>1072)throw new IOException("PKARR 公告过大");return PkarrPacket.Read(key,bytes.AsSpan(0,used),DateTimeOffset.UtcNow);}catch(Exception ex)when(ex is HttpRequestException or IOException or FormatException or JsonException or CryptographicException or OperationCanceledException){return null;}
        }));token.ThrowIfCancellationRequested();var record=reads.Where(r=>r!=null).OrderByDescending(r=>r!.Sequence).FirstOrDefault()??throw new IOException("PKARR 暂未取得有效公告，请检查主机发布状态或稍后重试");
        lock(cacheGate){if(newest.TryGetValue(key,out var prior)&&(record.Sequence<prior.Sequence||record.Sequence==prior.Sequence&&!record.Packet.SequenceEqual(prior.Packet)))throw new IOException("PKARR 网关返回了旧公告或冲突公告");if(newest.Count>=256&&!newest.ContainsKey(key))newest.Remove(newest.Keys.First());newest[key]=record;}
        if(record.Announcement.Mode!=mode)throw new IOException("PKARR 公告协议与当前网络不一致，不自动切换协议");return record.Announcement.Endpoints.Distinct().ToArray();
    }
    public async Task<int> Publish(string seed,byte[] packet,CancellationToken token)
    {
        string key=PkarrPacket.PublicKey(seed);var results=await Task.WhenAll(gateways.Select(async gateway=>{try{using var request=new HttpRequestMessage(HttpMethod.Put,gateway.TrimEnd('/')+"/"+key){Content=new ByteArrayContent(packet)};request.Content.Headers.ContentType=new("application/octet-stream");using var response=await http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,token);return response.IsSuccessStatusCode;}catch(Exception ex)when(ex is HttpRequestException or IOException or OperationCanceledException){return false;}}));token.ThrowIfCancellationRequested();int accepted=results.Count(v=>v);if(accepted==0)throw new IOException("PKARR 公告暂未发布成功，现有入口与连接保留");return accepted;
    }
    public void Dispose(){if(owned)http.Dispose();}
}
