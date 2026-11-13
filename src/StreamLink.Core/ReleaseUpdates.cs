using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace StreamLink.Core;

public sealed record ReleaseUpdatePackage(string Name,string Url,long Bytes,string Sha256);
public sealed record ReleaseUpdateStatus(string CurrentVersion,string Platform,string State="NotChecked",string Message="尚未检查更新")
{
    public string LatestVersion {get;init;}="";
    public string ReleaseUrl {get;init;}="";
    public string Notes {get;init;}="";
    public bool UpdateAvailable {get;init;}
    public long CheckedAt {get;init;}
    public ReleaseUpdatePackage? Package {get;init;}
}

// Public release metadata only: no credentials, network IDs or device names.
// This client never downloads or executes an installer or modifies settings.
public sealed class ReleaseUpdateClient : IDisposable
{
    public const string Repository="https://github.com/MrSGSA/ConWU";
    public const string Feed="https://api.github.com/repos/MrSGSA/ConWU/releases/latest";
    const int MaximumResponseBytes=262144;
    readonly HttpClient http;
    readonly bool ownsClient;
    public static string CurrentVersion=>typeof(ReleaseUpdateClient).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion??"unknown";
    public static string CurrentPlatform=>OperatingSystem.IsAndroid()?"android":OperatingSystem.IsIOS()?"ios":OperatingSystem.IsWindows()?"windows":OperatingSystem.IsLinux()?"linux":"unknown";
    public static string CurrentArchitecture=>RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();
    public ReleaseUpdateClient(HttpClient? client=null)
    {
        ownsClient=client==null;
        http=client??new(new SocketsHttpHandler{AllowAutoRedirect=false,UseCookies=false,ConnectTimeout=TimeSpan.FromSeconds(4),
            PooledConnectionLifetime=TimeSpan.FromMinutes(5),MaxConnectionsPerServer=2,AutomaticDecompression=DecompressionMethods.GZip|DecompressionMethods.Deflate}){Timeout=Timeout.InfiniteTimeSpan};
    }
    public async Task<ReleaseUpdateStatus> Check(string current,string platform,string architecture,CancellationToken token=default)
    {
        if(!ReleaseVersion.TryParse(current,out var installed))throw new FormatException("无法识别当前软件版本");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(TimeSpan.FromSeconds(10));
        using var request=new HttpRequestMessage(HttpMethod.Get,Feed);
        request.Headers.UserAgent.ParseAdd("ConWU-UpdateCheck/1");request.Headers.Accept.ParseAdd("application/vnd.github+json");
        request.Headers.Add("X-GitHub-Api-Version","2022-11-28");
        using var response=await http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,deadline.Token);
        if(response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)throw new IOException("更新服务暂时限制查询，请稍后重试");
        if(!response.IsSuccessStatusCode)throw new IOException("暂时无法读取正式版发布信息");
        if(response.Content.Headers.ContentLength>MaximumResponseBytes)throw new FormatException("更新服务返回的数据过大");
        await using var stream=await response.Content.ReadAsStreamAsync(deadline.Token);
        using var bytes=new MemoryStream();byte[] buffer=new byte[8192];
        while(true){int count=await stream.ReadAsync(buffer,deadline.Token);if(count==0)break;if(bytes.Length+count>MaximumResponseBytes)throw new FormatException("更新服务返回的数据过大");bytes.Write(buffer,0,count);}
        return Parse(bytes.ToArray(),current,platform,architecture,installed!);
    }
    static ReleaseUpdateStatus Parse(byte[] bytes,string current,string platform,string architecture,ReleaseVersion installed)
    {
        using var document=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=16});
        var root=document.RootElement;
        static string Text(JsonElement item,string key,int maximum){if(!item.TryGetProperty(key,out var field)||field.ValueKind!=JsonValueKind.String||field.GetString() is not {} value||value.Length>maximum)throw new FormatException("更新服务返回的版本信息无效");return value;}
        if(root.ValueKind!=JsonValueKind.Object||!root.TryGetProperty("draft",out var draft)||draft.ValueKind!=JsonValueKind.False||
            !root.TryGetProperty("prerelease",out var preview)||preview.ValueKind!=JsonValueKind.False)throw new FormatException("更新服务没有返回正式发布版本");
        string tag=Text(root,"tag_name",256);
        if(!ReleaseVersion.TryParse(tag,out var latest)||!latest!.Stable)throw new FormatException("更新服务返回的版本号无效");
        string release=Repository+"/releases/tag/"+Uri.EscapeDataString(tag);
        if(Text(root,"html_url",2048)!=release)throw new FormatException("更新页面不属于 ConWU 官方仓库");
        string notes=root.TryGetProperty("body",out var body)&&body.ValueKind==JsonValueKind.String?body.GetString()??"":"";
        if(notes.Length>16384)notes=notes[..16384];
        if(!root.TryGetProperty("assets",out var assets)||assets.ValueKind!=JsonValueKind.Array||assets.GetArrayLength()>128)throw new FormatException("更新附件列表无效");
        var packages=new Dictionary<string,ReleaseUpdatePackage>(StringComparer.OrdinalIgnoreCase);
        foreach(var item in assets.EnumerateArray()){
            string name=Text(item,"name",256);
            if(name.Length==0||name.Any(c=>char.IsControl(c)||c is '/' or '\\'))throw new FormatException("更新附件名称无效");
            if(item.TryGetProperty("state",out var state)&&state.GetString()!="uploaded")continue;
            string url=Text(item,"browser_download_url",2048);
            if(url!=Repository+"/releases/download/"+Uri.EscapeDataString(tag)+"/"+Uri.EscapeDataString(name))throw new FormatException("更新附件不属于 ConWU 官方发布");
            if(!item.TryGetProperty("size",out var size)||!size.TryGetInt64(out long length)||length<=0)continue;
            string hash="";
            if(item.TryGetProperty("digest",out var digest)&&digest.ValueKind==JsonValueKind.String){
                string value=digest.GetString()!;
                if(!value.StartsWith("sha256:",StringComparison.Ordinal)||value.Length!=71||!value.AsSpan(7).ToString().All(char.IsAsciiHexDigit))throw new FormatException("更新附件的校验信息无效");
                hash=value[7..].ToUpperInvariant();
            }
            if(!packages.TryAdd(name,new(name,url,length,hash)))throw new FormatException("更新附件名称重复");
        }
        string version=latest.ToString(),prefix="ConWU-"+version;
        string[] names=(platform,architecture) switch{
            ("windows","x64")=>[prefix+"-x64.msi",prefix+"-windows-x64.zip"],
            ("windows","arm64")=>[prefix+"-windows-arm64.msi",prefix+"-windows-arm64.zip"],
            ("linux","x64")=>[prefix+"-linux-x64.tar.gz"],
            ("linux","arm64")=>[prefix+"-linux-arm64.tar.gz"],
            ("android",_)=>[prefix+"-android-"+(architecture switch{"arm64"=>"arm64-v8a","arm"=>"armeabi-v7a","x64"=>"x86_64",_=>"unsupported"})+".apk",prefix+"-android-universal.apk",prefix+"-android.apk"],
            _=>[]
        };
        var package=names.Select(n=>packages.GetValueOrDefault(n)).FirstOrDefault(p=>p!=null);
        bool newer=latest.CompareTo(installed)>0;
        return new(current,platform,newer?package==null?"NoPackage":"Available":"UpToDate",newer?
            package==null?platform=="ios"?"有新版本，请从原安装渠道更新":"有新版本，暂未提供此平台的安装包":"发现新版本 "+version:"暂无更高版本的正式版"){
            LatestVersion=version,ReleaseUrl=release,Notes=notes,UpdateAvailable=newer,Package=package
        };
    }
    public void Dispose(){if(ownsClient)http.Dispose();}
}

// One shared request per monitor; UI polling and caller cancellation cannot
// interrupt another caller or delay connection/status operations.
public sealed class ReleaseUpdateMonitor : IDisposable
{
    readonly ReleaseUpdateClient client;
    readonly TimeProvider clock;
    readonly string current,platform,architecture;
    readonly object gate=new();
    readonly CancellationTokenSource stop=new();
    ReleaseUpdateStatus status;
    Task<ReleaseUpdateStatus>? pending;
    DateTimeOffset nextAutomatic,nextManual;
    bool disposed;
    public ReleaseUpdateMonitor(ReleaseUpdateClient? client=null,string? current=null,string? platform=null,string? architecture=null,TimeProvider? clock=null)
    {
        this.client=client??new();this.clock=clock??TimeProvider.System;this.current=current??ReleaseUpdateClient.CurrentVersion;
        this.platform=platform??ReleaseUpdateClient.CurrentPlatform;this.architecture=architecture??ReleaseUpdateClient.CurrentArchitecture;
        status=new(this.current,this.platform);
    }
    public ReleaseUpdateStatus Status=>Volatile.Read(ref status);
    public Task<ReleaseUpdateStatus> Check(bool force=false,CancellationToken token=default)
    {
        token.ThrowIfCancellationRequested();
        lock(gate){
            if(disposed)throw new ObjectDisposedException(nameof(ReleaseUpdateMonitor));
            if(pending is {IsCompleted:false})return pending.WaitAsync(token);
            var now=clock.GetUtcNow();
            if(now<(force?nextManual:nextAutomatic))return Task.FromResult(Status);
            nextManual=now.AddMinutes(1);
            Volatile.Write(ref status,Status with{State="Checking",Message="正在检查更新"});
            pending=Task.Run(Run,CancellationToken.None);return pending.WaitAsync(token);
        }
    }
    async Task<ReleaseUpdateStatus> Run()
    {
        ReleaseUpdateStatus result;
        try{result=await client.Check(current,platform,architecture,stop.Token);}
        catch(OperationCanceledException){result=Status with{State="Error",Message="更新检查超时或已取消，连接不受影响"};}
        catch(Exception ex)when(ex is HttpRequestException or IOException or FormatException or JsonException or InvalidOperationException or ArgumentException){
            result=Status with{State="Error",Message="暂时无法检查更新，请稍后重试；连接不受影响"};
        }
        lock(gate){
            result=result with{CheckedAt=clock.GetUtcNow().ToUnixTimeSeconds()};
            if(!disposed){nextAutomatic=clock.GetUtcNow().Add(result.State=="Error"?TimeSpan.FromMinutes(15):TimeSpan.FromHours(24));Volatile.Write(ref status,result);}
        }
        return result;
    }
    public void Dispose(){lock(gate){if(disposed)return;disposed=true;}stop.Cancel();client.Dispose();}
}
