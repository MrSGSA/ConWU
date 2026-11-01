using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace StreamLink.Core;

public sealed record ExistingEntry(int PeerSlot, string Source);
public sealed record EntryResolution(int PeerSlot, int Index, string Kind, string[] Endpoints, string Error);

// These are hints, never membership credentials or proof of connectivity.
// Fetch only explicitly configured sources. Never follow returned URLs.
public sealed class ExistingEntryResolver : IDisposable
{
    public const int MaximumSources = 12, MaximumEndpoints = 8, MaximumBody = 8192;
    readonly HttpClient http;
    readonly Func<string, CancellationToken, Task<IPAddress[]>> addresses;
    readonly Func<string, CancellationToken, Task<string[]>> txt;
    public ExistingEntryResolver() : this((host, ct) => Dns.GetHostAddressesAsync(host, ct), DnsTextLookup.Query) { }
    internal ExistingEntryResolver(Func<string,CancellationToken,Task<IPAddress[]>> addresses,
        Func<string,CancellationToken,Task<string[]>> txt, HttpMessageHandler? handler = null)
    {
        this.addresses = addresses; this.txt = txt;
        http = new(handler ?? new SocketsHttpHandler {
            UseProxy=false, AllowAutoRedirect=false, UseCookies=false, MaxConnectionsPerServer=2,
            ConnectCallback=async (context, ct) => {
                var ips = await addresses(context.DnsEndPoint.Host, ct);
                // Pin DNS resolution to the actual connection, including redirects (disabled).
                if (ips.Length == 0 || ips.Any(ip => !PublicAddress(ip))) throw new IOException("更新页面必须使用公网地址");
                var ip = ips.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork) ?? ips[0];
                var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try { await socket.ConnectAsync(new IPEndPoint(ip, context.DnsEndPoint.Port), ct); return new NetworkStream(socket, true); }
                catch { socket.Dispose(); throw; }
            }
        }) { Timeout=TimeSpan.FromSeconds(4), MaxResponseContentBufferSize=MaximumBody };
    }
    public static string Kind(string source) => source.StartsWith("txt://", StringComparison.OrdinalIgnoreCase) ? "TXT" :
        source.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? "HTTPS" : source.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ? "HTTP" : "地址";
    public static void Validate(ExistingEntry[]? entries)
    {
        if (entries == null || entries.Length > MaximumSources) throw new FormatException("已有入口最多填写 12 项");
        foreach (var entry in entries) {
            if (entry == null || entry.PeerSlot is < 0 or > 254 || entry.Source is not {Length: >0 and <=2048} s || s.Any(char.IsControl) || s != s.Trim())
                throw new FormatException("入口归属或地址无效");
            if (Kind(s) == "TXT") { if (!Host(s[6..])) throw new FormatException("TXT 地址格式为 txt://完整域名"); }
            else if (Kind(s) is "HTTP" or "HTTPS") {
                if (!Uri.TryCreate(s, UriKind.Absolute, out var uri) || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 || !Host(uri.Host) || uri.IsLoopback)
                    throw new FormatException("更新页面需为不含用户名和片段的 HTTP(S) 公网地址");
                if (IPAddress.TryParse(uri.Host, out var ip) && !PublicAddress(ip)) throw new FormatException("更新页面不能指向本机或内网服务");
            } else ParseEndpoint(s);
        }
    }
    static bool Host(string host) => host.Length is >0 and <=253 && host.Split('.').All(label => label.Length is >0 and <=63 && label.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'));
    public static (string Host,int Port) ParseEndpoint(string value)
    {
        // Scheme describes the selected wire protocol; HTTP URLs always mean an update document.
        if (value.StartsWith("tcp://",StringComparison.OrdinalIgnoreCase)) value=value[6..];
        else if (value.StartsWith("udp://",StringComparison.OrdinalIgnoreCase)) value=value[6..];
        int colon=value.LastIndexOf(':');
        if (colon<=0 || !Host(value[..colon]) || !int.TryParse(value[(colon+1)..],out int port) || port is <1 or >65535)
            throw new FormatException("入口应为 IPv4:端口、域名:端口、txt://域名或 HTTP(S) 更新页面；暂不支持 IPv6 入口");
        if (IPAddress.TryParse(value[..colon],out var ip) && !EndpointAddress(ip)) throw new FormatException("入口不能是回环、链路本地或组播地址");
        return (value[..colon],port);
    }
    public static bool EndpointAddress(IPAddress ip)
    {
        if (ip.AddressFamily!=AddressFamily.InterNetwork) return false;
        var b=ip.GetAddressBytes();
        return b[0] is >0 and <224 && b[0]!=127 && !(b[0]==169 && b[1]==254) && !(b[0]==192 && b[1]==0 && b[2]==0);
    }
    static bool PublicAddress(IPAddress ip)
    {
        if(ip.AddressFamily==AddressFamily.InterNetworkV6) {
            if(ip.IsIPv4MappedToIPv6)return PublicAddress(ip.MapToIPv4());
            var b=ip.GetAddressBytes();return (b[0]&0xe0)==0x20; // global unicast only
        }
        if(!EndpointAddress(ip))return false;
        var v=ip.GetAddressBytes();return v[0]!=10 && !(v[0]==172&&v[1]>=16&&v[1]<=31) && !(v[0]==192&&v[1]==168) && !(v[0]==100&&v[1]>=64&&v[1]<=127) && !(v[0]==198&&v[1] is 18 or 19);
    }
    public async Task<EntryResolution[]> Resolve(ExistingEntry[] entries, string mode, CancellationToken token)
    {
        Validate(entries);
        using var total=CancellationTokenSource.CreateLinkedTokenSource(token);total.CancelAfter(12000);
        using var limit=new SemaphoreSlim(2);
        return await Task.WhenAll(entries.Select(async (entry,index) => {
            bool acquired=false;
            try {await limit.WaitAsync(total.Token);acquired=true;return await ResolveOne(entry,index,mode,total.Token);}
            catch(OperationCanceledException)when(!token.IsCancellationRequested){return new EntryResolution(entry.PeerSlot,index,Kind(entry.Source),[],"本轮解析已超时");}
            finally {if(acquired)limit.Release();}
        }));
    }
    async Task<EntryResolution> ResolveOne(ExistingEntry entry,int index,string mode,CancellationToken token)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(4500);
        string kind=Kind(entry.Source);
        try {
            string[] values;
            if(kind=="TXT") values=(await txt(entry.Source[6..],deadline.Token)).SelectMany(ParseDocument).ToArray();
            else if(kind is "HTTP" or "HTTPS") {
                using var response=await http.GetAsync(entry.Source,HttpCompletionOption.ResponseHeadersRead,deadline.Token);
                response.EnsureSuccessStatusCode();
                if(response.Content.Headers.ContentLength>MaximumBody)throw new IOException("更新内容超过 8 KiB");
                using var stream=await response.Content.ReadAsStreamAsync(deadline.Token);
                var bytes=new byte[MaximumBody+1];int size=0,read;
                while(size<bytes.Length && (read=await stream.ReadAsync(bytes.AsMemory(size),deadline.Token))>0)size+=read;
                if(size>MaximumBody)throw new IOException("更新内容超过 8 KiB");
                values=ParseDocument(new UTF8Encoding(false,true).GetString(bytes,0,size));
            } else values=[entry.Source];
            if(values.Length is 0 or >MaximumEndpoints)throw new FormatException("每项来源须返回 1–8 个入口");
            var endpoints=new List<string>();
            foreach(var value in values) {
                if(value.StartsWith("udp://",StringComparison.OrdinalIgnoreCase) && mode!="udp" || value.StartsWith("tcp://",StringComparison.OrdinalIgnoreCase) && mode!="faketcp")
                    throw new FormatException("入口协议与用户选定模式不一致");
                var (host,port)=ParseEndpoint(value);
                var ips=IPAddress.TryParse(host,out var literal)?[literal]:await addresses(host,deadline.Token);
                foreach(var ip in ips.Where(EndpointAddress)) if(!endpoints.Contains(new IPEndPoint(ip,port).ToString())) endpoints.Add(new IPEndPoint(ip,port).ToString());
                if(endpoints.Count>MaximumEndpoints)throw new FormatException("解析结果超过 8 个入口");
            }
            if(endpoints.Count==0)throw new IOException("没有可用的 IPv4 入口");
            return new(entry.PeerSlot,index,kind,endpoints.ToArray(),"");
        } catch(Exception ex) when(!token.IsCancellationRequested && ex is IOException or HttpRequestException or SocketException or OperationCanceledException or FormatException or JsonException or DecoderFallbackException) {
            // Never echo a URL/query, body, or provider token into logs.
            string reason=ex switch { OperationCanceledException=>"解析超时",HttpRequestException=>"更新页面访问失败",SocketException=>"域名解析失败",FormatException=>ex.Message,_=>"更新内容无效或暂不可用" };
            return new(entry.PeerSlot,index,kind,[],reason);
        }
    }
    internal static string[] ParseDocument(string text)
    {
        text=text.Trim();
        if(text.StartsWith("streamlink=",StringComparison.OrdinalIgnoreCase))text=text[11..].Trim();
        if(text.StartsWith('{') || text.StartsWith('[')) {
            using var doc=JsonDocument.Parse(text,new(){MaxDepth=4});var root=doc.RootElement;
            if(root.ValueKind==JsonValueKind.Object)root=root.TryGetProperty("endpoints",out var endpoints)?endpoints:root.TryGetProperty("addresses",out var addresses)?addresses:throw new FormatException("JSON 须包含 endpoints 数组");
            if(root.ValueKind!=JsonValueKind.Array)throw new FormatException("JSON 须包含 endpoints 数组");
            return root.EnumerateArray().Select(e=>e.ValueKind==JsonValueKind.String?e.GetString()!.Trim():throw new FormatException("入口必须为字符串")).ToArray();
        }
        return text.Split(['\r','\n',',',';',' ','\t'],StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries);
    }
    public void Dispose()=>http.Dispose();
}
