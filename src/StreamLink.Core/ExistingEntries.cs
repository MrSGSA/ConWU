using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace StreamLink.Core;

public sealed record ExistingEntry(int PeerSlot, string Source)
{
    // Stable before enrollment: connects to the network owner, never publishes
    // this address as the joining device's own ingress.
    public const int NetworkOwner = -1;
    public const int Network = -2;
    public static ExistingEntry[] ForJoinedNetwork(ExistingEntry[] entries) => entries.Where(e=>e.PeerSlot is 0 or NetworkOwner or Network)
        .Select(e=>e.PeerSlot==NetworkOwner?e with {PeerSlot=1}:e).Distinct().ToArray();
}
public sealed record EntryResolution(int PeerSlot, int Index, string Kind, string[] Endpoints, string Error)
{
    public long ElapsedMs {get;init;}
    public int Attempts {get;init;}
    // Zero is legacy unbounded hint data. Signed DDNS records carry
    // an absolute deadline which remains binding through cached failures.
    public long ExpiresAt {get;init;}
    public bool AllowCached {get;init;}=true;
}

// These are hints, never membership credentials or proof of connectivity.
// Fetch only explicitly configured sources. Never follow returned URLs.
public sealed class ExistingEntryResolver : IDisposable
{
    public const int MaximumSources = 12, MaximumEndpoints = 8, MaximumBody = 8192;
    readonly HttpClient http;
    readonly Func<string, CancellationToken, Task<IPAddress[]>> addresses;
    readonly Func<string, CancellationToken, Task<string[]>> txt;
    readonly Func<long> utcNow;
    internal static readonly HttpRequestOptionsKey<FetchProgress> ProgressKey = new("StreamLink.EntryProgress");
    internal sealed class FetchProgress { public string Stage = "连接／TLS／响应头"; public int Attempt; public IPAddress? LastConnected; }
    readonly Func<IPEndPoint,CancellationToken,Task<Stream>> connect;
    public ExistingEntryResolver() : this((host, ct) => Dns.GetHostAddressesAsync(host, ct), DnsTextLookup.Query) { }
    internal ExistingEntryResolver(Func<string,CancellationToken,Task<IPAddress[]>> addresses,
        Func<string,CancellationToken,Task<string[]>> txt, HttpMessageHandler? handler = null,
        Func<IPEndPoint,CancellationToken,Task<Stream>>? connect = null, Func<long>? utcNow = null)
    {
        this.utcNow = utcNow ?? (() => DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        this.addresses = addresses; this.txt = txt; this.connect = connect ?? ConnectSocket;
        http = new(handler ?? new SocketsHttpHandler {
            UseProxy=false, AllowAutoRedirect=false, UseCookies=false, MaxConnectionsPerServer=2,
            PooledConnectionIdleTimeout=TimeSpan.FromMinutes(5),PooledConnectionLifetime=TimeSpan.FromMinutes(10),
            ConnectCallback=async (context, ct) => {
                context.InitialRequestMessage.Options.TryGetValue(ProgressKey,out var progress);
                return await ConnectPage(context.DnsEndPoint,progress??new(),ct);
            }
        }) { Timeout=Timeout.InfiniteTimeSpan, MaxResponseContentBufferSize=MaximumBody };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("StreamLink/"+(typeof(ExistingEntryResolver).Assembly.GetName().Version?.ToString(3)??"1.0"));
    }
    static async Task<Stream> ConnectSocket(IPEndPoint endpoint,CancellationToken token)
    {
        var socket=new Socket(endpoint.AddressFamily,SocketType.Stream,ProtocolType.Tcp);
        try {await socket.ConnectAsync(endpoint,token);return new NetworkStream(socket,true);}
        catch {socket.Dispose();throw;}
    }
    internal async Task<Stream> ConnectPage(DnsEndPoint endpoint,FetchProgress progress,CancellationToken token)
    {
        progress.Stage="DNS 查询";
        var ips=await addresses(endpoint.Host,token);
        // Validate the WHOLE answer before connecting, then pin each attempted
        // socket. Never follow redirects, use a proxy, or retry a private answer.
        if(ips.Length==0||ips.Any(ip=>!PublicAddress(ip)))throw new EntryFetchException("更新页面必须使用公网地址");
        var v4=ips.Where(ip=>ip.AddressFamily==AddressFamily.InterNetwork).Distinct().ToArray();
        var v6=ips.Where(ip=>ip.AddressFamily==AddressFamily.InterNetworkV6).Distinct().ToArray();
        var ordered=Enumerable.Range(0,Math.Max(v4.Length,v6.Length)).SelectMany(i=>new[]{i<v4.Length?v4[i]:null,i<v6.Length?v6[i]:null}).OfType<IPAddress>().Take(3).ToArray();
        if(progress.LastConnected is {} previous)ordered=ordered.OrderBy(ip=>ip.Equals(previous)?1:0).ToArray();
        if(ordered.Length==0)throw new EntryFetchException("无可用公网地址");
        progress.Stage=$"TCP 建连（{ordered.Length} 个地址）";
        using var race=CancellationTokenSource.CreateLinkedTokenSource(token);
        async Task<Stream> Dial(IPAddress address,int index){
            if(index>0)await Task.Delay(index*200,race.Token);
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(race.Token);deadline.CancelAfter(4000);
            return await connect(new(address,endpoint.Port),deadline.Token);
        }
        // Stagger a bounded number of already-validated addresses. One blackholed
        // address must not consume the whole TLS budget or prevent another family
        // from connecting. Every losing socket is cancelled, joined and disposed.
        var attempts=ordered.Select((ip,index)=>(Address:ip,Task:Dial(ip,index))).ToArray();
        var pending=attempts.Select(a=>a.Task).ToList();Task<Stream>? winner=null;
        try {
            while(pending.Count>0){
                var completed=await Task.WhenAny(pending);pending.Remove(completed);
                try {
                    var stream=await completed;winner=completed;
                    progress.LastConnected=attempts.First(a=>ReferenceEquals(a.Task,winner)).Address;
                    progress.Stage="TLS／响应头";return stream;
                }catch(Exception ex)when(!token.IsCancellationRequested&&ex is SocketException or IOException or OperationCanceledException){}
            }
            token.ThrowIfCancellationRequested();throw new EntryFetchException("TCP 建连失败或超时",true);
        }finally{
            race.Cancel();
            foreach(var attempt in attempts.Where(a=>!ReferenceEquals(a.Task,winner)))try{(await attempt.Task).Dispose();}catch{}
        }
    }
    sealed class EntryFetchException(string message,bool transient=false):IOException(message) {public bool Transient {get;}=transient;}
    static EntryFetchException? FetchFailure(Exception ex)=>ex as EntryFetchException??(ex.InnerException==null?null:FetchFailure(ex.InnerException));
    static bool Retryable(Exception ex)=>FetchFailure(ex) is {} known?known.Transient:ex is OperationCanceledException or HttpIOException {HttpRequestError:HttpRequestError.ResponseEnded} ||
        ex is HttpRequestException request && request.HttpRequestError is HttpRequestError.ConnectionError or HttpRequestError.NameResolutionError or HttpRequestError.ResponseEnded;
    async Task<string[]> Fetch(string source,FetchProgress progress,CancellationToken token)
    {
        for(int attempt=1;;attempt++) {
            progress.Attempt=attempt;progress.Stage="连接／TLS／响应头";
            using var budget=CancellationTokenSource.CreateLinkedTokenSource(token);budget.CancelAfter(6500);
            try {
                using var request=new HttpRequestMessage(HttpMethod.Get,WithoutSelector(source));
                request.Options.Set(ProgressKey,progress);request.Headers.CacheControl=new(){NoCache=true,NoStore=true};
                using var response=await http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,budget.Token);
                if(!response.IsSuccessStatusCode)throw await ResponseFailure(response,budget.Token);
                progress.Stage="响应内容";
                if(response.Content.Headers.ContentLength>MaximumBody)throw new EntryFetchException("更新内容超过 8 KiB");
                using var stream=await response.Content.ReadAsStreamAsync(budget.Token);
                var bytes=new byte[MaximumBody+1];int size=0,read;
                while(size<bytes.Length&&(read=await stream.ReadAsync(bytes.AsMemory(size),budget.Token))>0)size+=read;
                if(size>MaximumBody)throw new EntryFetchException("更新内容超过 8 KiB");
                progress.Stage="内容解析";return ParseDocuments([new UTF8Encoding(false,true).GetString(bytes,0,size)],RequiresTag(source),Selector(source));
            }catch(Exception ex)when(attempt==1&&!token.IsCancellationRequested&&Retryable(ex)) {await Task.Delay(200,token);}
        }
    }
    static async Task<EntryFetchException> ResponseFailure(HttpResponseMessage response,CancellationToken token)
    {
        int code=(int)response.StatusCode;
        var failure=new EntryFetchException($"更新页面返回 HTTP {code}",response.StatusCode is HttpStatusCode.RequestTimeout or HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout);
        if(response.StatusCode is not (HttpStatusCode.ServiceUnavailable or HttpStatusCode.NotFound) ||
            !string.Equals(response.Content.Headers.ContentType?.MediaType,"application/json",StringComparison.OrdinalIgnoreCase) || response.Content.Headers.ContentLength>1024)return failure;
        // Only recognize exact provider error codes. Never echo arbitrary error
        // bodies: they may contain URLs, bearer tokens or private configuration.
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(token);budget.CancelAfter(750);
        try {
            using var stream=await response.Content.ReadAsStreamAsync(budget.Token);
            byte[] bytes=new byte[1025];int size=0,read;
            while(size<bytes.Length&&(read=await stream.ReadAsync(bytes.AsMemory(size),budget.Token))>0)size+=read;
            if(size>1024)return failure;
            using var doc=JsonDocument.Parse(bytes.AsMemory(0,size),new(){MaxDepth=4});
            if(doc.RootElement.ValueKind!=JsonValueKind.Object || !doc.RootElement.TryGetProperty("error",out var error) || error.ValueKind!=JsonValueKind.String)return failure;
            return (response.StatusCode,error.GetString()) switch {
                (HttpStatusCode.ServiceUnavailable,"entry report expired" or "节点 a 地址已过期" or "节点 b 地址已过期") => new("入口上报已过期，请检查主机的地址更新任务（HTTP 503）"),
                (HttpStatusCode.NotFound,"awaiting Lucky report") => new("更新服务尚未收到入口上报（HTTP 404）"),
                (HttpStatusCode.ServiceUnavailable,"registry not configured") => new("入口订阅服务尚未配置（HTTP 503）"),
                (HttpStatusCode.ServiceUnavailable,"registry temporarily unavailable") => new("入口订阅服务暂时无法读取上报数据（HTTP 503）",true),
                _ => failure
            };
        }catch(OperationCanceledException)when(!token.IsCancellationRequested){return failure;}
        catch(Exception ex)when(ex is IOException or JsonException){return failure;}
    }
    public static string NormalizeSource(string source)=>!source.Contains("://",StringComparison.Ordinal)&&source.Contains('#')?"txt://"+source:source;
    public static string Kind(string source) => NormalizeSource(source).StartsWith("txt://", StringComparison.OrdinalIgnoreCase)?"TXT":
        source.StartsWith("pkarr://",StringComparison.Ordinal)?"PKARR":
        source.StartsWith("txt://", StringComparison.OrdinalIgnoreCase) ? "TXT" :
        source.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? "HTTPS" : source.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ? "HTTP" : "地址";
    static string? Selector(string source)
    {
        int hash=source.IndexOf('#');if(hash<0)return null;
        string tag=source[(hash+1)..];
        if(tag.Length is <1 or >32||!char.IsAsciiLetter(tag[0])||tag.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c is not ('_' or '-')))throw new FormatException("入口标签需为 1–32 位字母、数字、下划线或短横线，以字母开头");
        return tag;
    }
    static bool RequiresTag(string source)=>Selector(source)!=null;
    static string WithoutSelector(string source){source=NormalizeSource(source);int hash=source.IndexOf('#');return hash<0?source:source[..hash];}
    public static void Validate(ExistingEntry[]? entries)
    {
        if (entries == null || entries.Length > MaximumSources) throw new FormatException("已有入口最多填写 12 项");
        foreach (var entry in entries) {
            if (entry == null || entry.PeerSlot is < ExistingEntry.Network or > 254 || entry.Source is not {Length: >0 and <=2048} s || s.Any(char.IsControl) || s != s.Trim())
                throw new FormatException("入口归属或地址无效");
            if(s.StartsWith("conwu-ddns:",StringComparison.OrdinalIgnoreCase))throw new FormatException("内置 DDNS 入口已停用，请改用普通地址或 HTTPS/TXT 订阅");
            _=Selector(s);
            if(Kind(s)=="PKARR"){PkarrPacket.KeyFromSource(s);}
            else if (Kind(s) == "TXT") { if (!Host(WithoutSelector(s)[6..])) throw new FormatException("TXT 地址格式为 txt://完整域名，可加 #streamlink1 等标签"); }
            else if (Kind(s) is "HTTP" or "HTTPS") {
                if (!Uri.TryCreate(WithoutSelector(s), UriKind.Absolute, out var uri) || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 || !Host(uri.Host) || uri.IsLoopback)
                    throw new FormatException("更新页面需为不含用户名的 HTTP(S) 公网地址，可使用 #streamlink1 选择对应标签");
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
        Validate(entries);entries=entries.Distinct().ToArray();
        using var total=CancellationTokenSource.CreateLinkedTokenSource(token);total.CancelAfter(30000);
        using var limit=new SemaphoreSlim(3);
        return await Task.WhenAll(entries.Select(async (entry,index) => {
            bool acquired=false;
            try {await limit.WaitAsync(total.Token);acquired=true;return await ResolveOne(entry,index,mode,total.Token);}
            catch(OperationCanceledException)when(!token.IsCancellationRequested){return new EntryResolution(entry.PeerSlot,index,Kind(entry.Source),[],"本轮解析已超时");}
            finally {if(acquired)limit.Release();}
        }));
    }
    async Task<EntryResolution> ResolveOne(ExistingEntry entry,int index,string mode,CancellationToken token)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(14000);
        long began=Environment.TickCount64;var progress=new FetchProgress {Stage="DNS 查询",Attempt=1};
        string kind=Kind(entry.Source);bool allowCached=true;
        try {
            string[] values;
            if(kind=="PKARR"){using var pkarr=new PkarrClient();progress.Stage="PKARR 公告查询";values=await pkarr.Resolve(entry.Source,mode,deadline.Token);}
            else if(kind=="TXT") values=ParseDocuments(await txt(WithoutSelector(entry.Source)[6..],deadline.Token),RequiresTag(entry.Source),Selector(entry.Source));
            else if(kind is "HTTP" or "HTTPS") values=await Fetch(entry.Source,progress,deadline.Token);
            else values=[entry.Source];
            progress.Stage="入口地址解析";
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
            return new(entry.PeerSlot,index,kind,endpoints.ToArray(),""){ElapsedMs=Environment.TickCount64-began,Attempts=progress.Attempt};
        } catch(Exception ex) when(!token.IsCancellationRequested && ex is IOException or UnauthorizedAccessException or HttpRequestException or SocketException or OperationCanceledException or FormatException or JsonException or DecoderFallbackException) {
            // Never echo a URL/query, body, or provider token into logs.
            string reason=FetchFailure(ex)?.Message??(ex switch { DnsTextLookupException=>ex.Message,OperationCanceledException=>progress.Stage+"超时",HttpRequestException {HttpRequestError:HttpRequestError.SecureConnectionError}=>"TLS 安全连接失败",HttpRequestException=>progress.Stage+"失败",SocketException=>"域名解析失败",FormatException=>ex.Message,_=>"更新内容无效或暂不可用" });
            long elapsed=Environment.TickCount64-began;
            return new(entry.PeerSlot,index,kind,[],reason+$"（{elapsed/1000d:F1} 秒，{progress.Attempt} 次）"){ElapsedMs=elapsed,Attempts=progress.Attempt,AllowCached=allowCached};
        }
    }
    // Select across the entire TXT answer / HTTP document, before parsing any
    // addresses. A foreign app's record must never poison or join a tagged set.
    internal static string[] ParseDocuments(IEnumerable<string> documents,bool requireTag=false,string? selectedTag=null)
    {
        var texts=documents.Select(s=>s.Trim()).ToArray();
        if(texts.Any(s=>s.Length>MaximumBody))throw new FormatException("更新内容超过 8 KiB");
        string prefix=(selectedTag??"streamlink")+"=";
        bool Tagged(string s)=>s.StartsWith(prefix,StringComparison.OrdinalIgnoreCase);
        bool TaggedJson(string s)=>Tagged(s)&&(s[prefix.Length..].TrimStart().StartsWith('{')||s[prefix.Length..].TrimStart().StartsWith('['));
        string[] Lines(string s)=>TaggedJson(s)?[s]:s.Split(['\r','\n'],StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries);
        IEnumerable<string> Tags(string record) {
            if(TaggedJson(record))return [record[prefix.Length..].Trim()];
            // One label owns one whitespace-delimited field. This also handles a
            // shared TXT RR: tcp://EasyTier:port streamlink=StreamLink:port.
            // Unlabelled fields after a tag still belong to other applications.
            return record.Split([' ','\t'],StringSplitOptions.RemoveEmptyEntries).Where(Tagged).Select(s=>s[prefix.Length..]);
        }
        var records=texts.SelectMany(Lines).ToArray();
        // A separate TXT RR may be arbitrary verification data, even invalid JSON.
        // Do not interpret it when explicit StreamLink records exist elsewhere.
        var tagged=records.SelectMany(Tags).ToArray();
        if(tagged.Length==0) {
            records=texts.SelectMany(s=>s.StartsWith('{')||s.StartsWith('[')?ParseJson(s):Lines(s)).ToArray();
            tagged=records.SelectMany(Tags).ToArray();
        }
        if(tagged.Length==0&&requireTag)throw new FormatException("订阅中没有 "+prefix+" 入口，请检查所选标签和更新内容");
        var values=new List<string>();
        foreach(var record in tagged.Length>0?tagged:records) {
            var parts=record.StartsWith('{')||record.StartsWith('[')?ParseJson(record):record.Split([' ',',',';','\t'],StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries);
            if(parts.Length==0)throw new FormatException("streamlink= 入口不能为空");
            values.AddRange(parts);
        }
        return values.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }
    internal static string[] ParseDocument(string text)=>ParseDocuments([text]);
    static string[] ParseJson(string text)
    {
        if(text.StartsWith('{') || text.StartsWith('[')) {
            using var doc=JsonDocument.Parse(text,new(){MaxDepth=4});var root=doc.RootElement;
            if(root.ValueKind==JsonValueKind.Object)root=root.TryGetProperty("endpoints",out var endpoints)?endpoints:root.TryGetProperty("addresses",out var addresses)?addresses:throw new FormatException("JSON 须包含 endpoints 数组");
            if(root.ValueKind!=JsonValueKind.Array)throw new FormatException("JSON 须包含 endpoints 数组");
            return root.EnumerateArray().Select(e=>e.ValueKind==JsonValueKind.String?e.GetString()!.Trim():throw new FormatException("入口必须为字符串")).ToArray();
        }
        throw new FormatException("入口 JSON 格式无效");
    }
    public void Dispose()=>http.Dispose();
}
