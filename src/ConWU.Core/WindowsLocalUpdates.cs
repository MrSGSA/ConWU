using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace StreamLink.Core;

// Privileged boundary: no URL, file path, command or SID is accepted from WebUI.
// Only official feed metadata, a prepared ticket, and the authorized local SID.
public sealed class WindowsLocalUpdateHost:ILocalUpdateHost
{
    public const string UpgradeCode="{AD076018-A9B8-47F5-B098-97479A363416}";
    readonly string root,worker;
    readonly HttpClient http;
    string? active;
    string? pruned;
    public bool Supported {get;}
    public WindowsLocalUpdateHost(string profileRoot,string? components=null)
    {
        root=Path.GetFullPath(Path.Combine(profileRoot,"updates"));worker=Path.Combine(components??Path.Combine(AppContext.BaseDirectory,"components"),"conwu-updater.exe");
        http=new(new SocketsHttpHandler{AllowAutoRedirect=false,UseCookies=false,ConnectTimeout=TimeSpan.FromSeconds(10),MaxConnectionsPerServer=2}){Timeout=Timeout.InfiniteTimeSpan};
        string pointer=Path.Combine(root,"active-job.id");
        if(File.Exists(pointer)){string id=ReadBounded(pointer,128).Trim();if(Guid.TryParseExact(id,"N",out _))active=Job(id);}
        Supported=OperatingSystem.IsWindows()&&File.Exists(worker)&&(HasInstalledMsi()||active!=null&&File.Exists(Path.Combine(active,"job.ini")));
    }
    static bool HasInstalledMsi()
    {
        if(!OperatingSystem.IsWindows())return false;
        var code=new StringBuilder(39);return MsiEnumRelatedProducts(WindowsInstance.IsValidation?Guid.Parse(WindowsInstance.ValidationId!).ToString("B"):UpgradeCode,0,0,code)==0;
    }
    string Job(string ticket)
    {
        if(!Guid.TryParseExact(ticket,"N",out _))throw new IOException("更新任务身份无效");
        string path=Path.GetFullPath(Path.Combine(root,"jobs",ticket));
        if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("更新目录越界");
        CheckAncestors(path);return path;
    }
    static void CheckAncestors(string path)
    {
        for(string? current=Path.GetFullPath(path);current!=null;current=Path.GetDirectoryName(current))
            if((File.Exists(current)||Directory.Exists(current))&&(File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0)throw new IOException("更新路径不能包含链接");
    }
    static string ReadBounded(string path,long maximum)
    {
        CheckAncestors(path);using var input=File.OpenRead(path);
        if(input.Length>maximum)throw new IOException("更新记录过大");
        using var reader=new StreamReader(input);return reader.ReadToEnd();
    }
    static void PrivateDirectory(string path)
    {
        CheckAncestors(path);Directory.CreateDirectory(path);
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
        var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null));
        foreach(var sid in new[]{WellKnownSidType.LocalSystemSid,WellKnownSidType.BuiltinAdministratorsSid})acl.AddAccessRule(new(new SecurityIdentifier(sid,null),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(acl);
    }
    public async Task<PreparedLocalUpdate> Download(ReleaseUpdateStatus release,Action<long,long> progress,CancellationToken token)
    {
        if(!Supported)throw new IOException("本机需要已安装的 MSI 版本及完整更新组件");
        var package=release.Package??throw new IOException("没有适用的安装包");
        string expected="ConWU-"+release.LatestVersion+"-x64.msi";
        string prefix=ReleaseUpdateClient.Repository+"/releases/tag/";
        string tag=release.ReleaseUrl.StartsWith(prefix,StringComparison.Ordinal)?release.ReleaseUrl[prefix.Length..]:"";
        if(tag!=release.LatestVersion&&tag!="v"+release.LatestVersion)throw new IOException("更新版本来源无效");
        if(ReleaseUpdateClient.CurrentArchitecture!="x64"||package.Name!=expected||package.Url!=ReleaseUpdateClient.Repository+"/releases/download/"+tag+"/"+expected||
            package.Bytes is <1024 or >1_073_741_824||package.Sha256.Length!=64||!package.Sha256.All(char.IsAsciiHexDigit))throw new IOException("更新包的来源、架构或校验信息不完整");
        string ticket=Guid.NewGuid().ToString("N"),directory=Job(ticket);PrivateDirectory(root);PrivateDirectory(directory);
        string partial=Path.Combine(directory,"package.partial"),target=Path.Combine(directory,"package.msi");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(TimeSpan.FromMinutes(15));
        Uri url=new(package.Url);HttpResponseMessage? response=null;
        try{
            for(int redirects=0;redirects<5;redirects++){
                using var request=new HttpRequestMessage(HttpMethod.Get,url);request.Headers.UserAgent.ParseAdd("ConWU-LocalUpdate/1");
                response=await http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,deadline.Token);
                if((int)response.StatusCode is >=300 and <=399){
                    var next=response.Headers.Location??throw new IOException("更新下载重定向无效");if(!next.IsAbsoluteUri)next=new(url,next);
                    if(next.Scheme!="https"||next.UserInfo.Length>0||!next.IsDefaultPort||next.Host is not("github.com" or "release-assets.githubusercontent.com" or "objects.githubusercontent.com"))throw new IOException("更新下载跳转到了未认可的来源");
                    response.Dispose();response=null;url=next;continue;
                }
                break;
            }
            if(response==null||!response.IsSuccessStatusCode)throw new IOException("暂时无法下载安装包");
            if(response.Content.Headers.ContentLength is {} bytes&&bytes!=package.Bytes)throw new IOException("安装包长度与发布信息不一致");
            await using(var input=await response.Content.ReadAsStreamAsync(deadline.Token))await using(var output=new FileStream(partial,FileMode.CreateNew,FileAccess.Write,FileShare.None,131072,FileOptions.Asynchronous|FileOptions.WriteThrough)){
                byte[] buffer=new byte[131072];long received=0;using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                while(true){int n=await input.ReadAsync(buffer,deadline.Token);if(n==0)break;received+=n;if(received>package.Bytes)throw new IOException("安装包超过预期长度");await output.WriteAsync(buffer.AsMemory(0,n),deadline.Token);hash.AppendData(buffer,0,n);progress(received,package.Bytes);}
                await output.FlushAsync(deadline.Token);
                if(received!=package.Bytes||!Convert.ToHexString(hash.GetHashAndReset()).Equals(package.Sha256,StringComparison.OrdinalIgnoreCase))throw new IOException("安装包下载不完整或校验失败，未停止网络");
            }
            ValidateMsi(partial);File.Move(partial,target,false);
            var ready=new PreparedLocalUpdate(ticket,release.LatestVersion,directory,target,package.Sha256,package.Bytes);
            AtomicWrite(Path.Combine(directory,"prepared.json"),JsonSerializer.Serialize(ready));
            AtomicWrite(Path.Combine(root,"ready-job.id"),ticket);PruneJobs();return ready;
        }finally{response?.Dispose();if(File.Exists(partial))File.Delete(partial);}
    }
    public PreparedLocalUpdate? RestorePrepared()
    {
        if(!Supported)return null;string pointer=Path.Combine(root,"ready-job.id");if(!File.Exists(pointer))return null;
        string ticket=ReadBounded(pointer,128).Trim(),folder=Job(ticket);
        // A launched job is always observed through the independent worker.
        if(active==folder)return null;
        var ready=JsonSerializer.Deserialize<PreparedLocalUpdate>(ReadBounded(Path.Combine(folder,"prepared.json"),16384))??throw new IOException("已下载的更新记录为空");
        if(ready.Ticket!=ticket||ready.Directory!=folder||ready.PackagePath!=Path.Combine(folder,"package.msi")||ready.Bytes is <1024 or >1_073_741_824||ready.Sha256.Length!=64||!ready.Sha256.All(char.IsAsciiHexDigit)||!ReleaseVersion.TryParse(ready.Version,out _))throw new IOException("已下载的更新记录不匹配");
        CheckAncestors(ready.PackagePath);using var file=File.OpenRead(ready.PackagePath);
        if(file.Length!=ready.Bytes||!Convert.ToHexString(SHA256.HashData(file)).Equals(ready.Sha256,StringComparison.OrdinalIgnoreCase))throw new IOException("已下载的安装包校验失败");
        ValidateMsi(ready.PackagePath);return ready;
    }
    public async Task Launch(PreparedLocalUpdate prepared,string callerSid,UpdateRecoveryState before,CancellationToken token)
    {
        if(!Supported||!OperatingSystem.IsWindows())throw new IOException("本机不支持 MSI 更新");
        var sid=new SecurityIdentifier(callerSid);if(!sid.IsAccountSid())throw new IOException("更新必须保留已授权的实际用户");
        string folder=Job(prepared.Ticket);if(folder!=prepared.Directory||Path.Combine(folder,"package.msi")!=prepared.PackagePath)throw new IOException("更新票据与本机文件不匹配");
        CheckAncestors(prepared.PackagePath);
        await using(var file=File.OpenRead(prepared.PackagePath))if(file.Length!=prepared.Bytes||!Convert.ToHexString(await SHA256.HashDataAsync(file,token)).Equals(prepared.Sha256,StringComparison.OrdinalIgnoreCase))throw new IOException("安装包在确认前发生变化");
        ValidateMsi(prepared.PackagePath);CheckAncestors(worker);
        File.Copy(worker,Path.Combine(folder,"conwu-updater.exe"),true);
        AtomicWrite(Path.Combine(folder,"recovery.json"),JsonSerializer.Serialize(new RecoveryJob(prepared.Ticket,prepared.Version,before.Networks.Where(n=>n.Enabled).ToArray())));
        string profile=Path.GetDirectoryName(root)!;
        string ini=$"[Update]\r\nTicket={prepared.Ticket}\r\nVersion={prepared.Version}\r\nService={WindowsInstance.Name}\r\nUiSid={sid.Value}\r\nSha256={prepared.Sha256}\r\nBytes={prepared.Bytes}\r\nProfileRoot={profile}\r\n";
        File.WriteAllText(Path.Combine(folder,"job.ini"),ini,Encoding.Unicode);
        if(active!=null&&active!=folder)AtomicWrite(Path.Combine(root,"previous-job.id"),Path.GetFileName(active));
        AtomicWrite(Path.Combine(root,"active-job.id"),prepared.Ticket);active=folder;
        var start=new ProcessStartInfo(Path.Combine(folder,"conwu-updater.exe")){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=folder};
        using var process=Process.Start(start)??throw new IOException("本机更新程序未能启动");
        string pointer=Path.Combine(root,"ready-job.id");CheckAncestors(pointer);if(File.Exists(pointer))File.Delete(pointer);
        // No parent-owned stdin, pipes, job object or cancellation token: the
        // updater keeps running when MSI stops this service and its WebUI.
    }
    public LocalUpdateStatus? ReadExternalStatus()
    {
        if(active==null)return null;string path=Path.Combine(active,"status.json");if(!File.Exists(path))return null;CheckAncestors(path);
        var status=JsonSerializer.Deserialize<LocalUpdateStatus>(ReadBounded(path,65536),new JsonSerializerOptions(JsonSerializerDefaults.Web));
        if(status?.Ticket==Path.GetFileName(active)&&status.State is "Completed" or "WaitingPeers"&&pruned!=active){PruneJobs();pruned=active;}
        return status is null||status.Ticket!=Path.GetFileName(active)?null:status with{Supported=Supported,CanInstall=false};
    }
    public void ReportRecovery(UpdateRecoveryState state)
    {
        if(active==null)return;string path=Path.Combine(active,"recovery.json");if(!File.Exists(path))return;
        var job=JsonSerializer.Deserialize<RecoveryJob>(ReadBounded(path,65536));if(job==null||job.Ticket!=Path.GetFileName(active)||job.Networks.Length>16)return;
        int restored=job.Networks.Count(n=>state.Networks.Any(live=>live.Id==n.Id&&live.NetworkId==n.NetworkId&&live.Enabled));
        int expected=job.Networks.Count(n=>n.Connected),connected=job.Networks.Count(n=>n.Connected&&state.Networks.Any(live=>live.Id==n.Id&&live.NetworkId==n.NetworkId&&live.Enabled&&live.Connected));
        string version=state.Version.Split('+')[0];
        string ini=$"[Health]\r\nTicket={job.Ticket}\r\nVersion={version}\r\nPid={Environment.ProcessId}\r\nReady={(state.Ready?1:0)}\r\nNetworksRestored={(restored==job.Networks.Length?1:0)}\r\nExpectedConnected={expected}\r\nConnected={connected}\r\n";
        string output=Path.Combine(active,"health.ini"),temp=output+".tmp";File.WriteAllText(temp,ini,Encoding.Unicode);File.Move(temp,output,true);
    }
    void PruneJobs()
    {
        // Retain current install, its single predecessor, the prepared package,
        // and every MSI source still registered for installed product repair.
        var keep=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(string name in new[]{"active-job.id","previous-job.id","ready-job.id"}){
            string pointer=Path.Combine(root,name);if(File.Exists(pointer))keep.Add(Job(ReadBounded(pointer,128).Trim()));
        }
        var sources=new List<string>();var product=new StringBuilder(39);
        string upgrade=WindowsInstance.IsValidation?Guid.Parse(WindowsInstance.ValidationId!).ToString("B"):UpgradeCode;
        for(uint i=0;MsiEnumRelatedProducts(upgrade,0,i,product)==0;i++){
            var source=new StringBuilder(32768);uint length=32768;
            if(MsiGetProductInfo(product.ToString(),"InstallSource",source,ref length)==0&&source.Length>0)sources.Add(Path.GetFullPath(source.ToString()).TrimEnd(Path.DirectorySeparatorChar));
        }
        string jobs=Path.Combine(root,"jobs");CheckAncestors(jobs);
        foreach(string path in Directory.EnumerateDirectories(jobs)){
            string id=Path.GetFileName(path);if(!Guid.TryParseExact(id,"N",out _)||keep.Contains(path)||sources.Any(s=>s.Equals(path,StringComparison.OrdinalIgnoreCase)||s.StartsWith(path+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)))continue;
            if(Job(id)!=path)throw new IOException("更新清理目录越界");
            // Check the entire tree before deleting anything from it.
            var pending=new Stack<string>();pending.Push(path);
            while(pending.TryPop(out var next)){CheckAncestors(next);foreach(string child in Directory.EnumerateFileSystemEntries(next)){CheckAncestors(child);if(Directory.Exists(child))pending.Push(child);}}
            Directory.Delete(path,true);
        }
    }
    static void AtomicWrite(string path,string text){CheckAncestors(path);string temp=path+".tmp";File.WriteAllText(temp,text,new UTF8Encoding(false));File.Move(temp,path,true);}
    sealed record RecoveryJob(string Ticket,string Version,UpdateNetworkState[] Networks);
    static void ValidateMsi(string path)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
        uint result=MsiOpenDatabase(path,0,out uint db);if(result!=0)throw new IOException("安装包不是有效的 MSI");
        try{
            string upgrade=Property(db,"UpgradeCode"),name=Property(db,"ProductName");
            string expected=WindowsInstance.IsValidation?Guid.Parse(WindowsInstance.ValidationId!).ToString("B"):UpgradeCode;
            if(!upgrade.Equals(expected,StringComparison.OrdinalIgnoreCase)||!name.StartsWith("ConWU",StringComparison.Ordinal))throw new IOException("MSI 不属于本机 ConWU 产品");
        }finally{MsiCloseHandle(db);}
    }
    static string Property(uint db,string key)
    {
        if(MsiDatabaseOpenView(db,"SELECT `Value` FROM `Property` WHERE `Property`='"+key+"'",out uint view)!=0)throw new IOException("MSI 属性读取失败");
        try{if(MsiViewExecute(view,0)!=0||MsiViewFetch(view,out uint row)!=0)throw new IOException("MSI 缺少产品属性");try{var text=new StringBuilder(512);uint count=512;return MsiRecordGetString(row,1,text,ref count)==0?text.ToString():throw new IOException("MSI 产品属性过大");}finally{MsiCloseHandle(row);}}
        finally{MsiCloseHandle(view);}
    }
    [DllImport("msi.dll",CharSet=CharSet.Unicode,EntryPoint="MsiEnumRelatedProductsW")]static extern uint MsiEnumRelatedProducts(string upgrade,uint reserved,uint index,StringBuilder product);
    [DllImport("msi.dll",CharSet=CharSet.Unicode,EntryPoint="MsiGetProductInfoW")]static extern uint MsiGetProductInfo(string product,string property,StringBuilder value,ref uint length);
    [DllImport("msi.dll",CharSet=CharSet.Unicode,EntryPoint="MsiOpenDatabaseW")]static extern uint MsiOpenDatabase(string path,nint persist,out uint handle);
    [DllImport("msi.dll",CharSet=CharSet.Unicode,EntryPoint="MsiDatabaseOpenViewW")]static extern uint MsiDatabaseOpenView(uint db,string query,out uint view);
    [DllImport("msi.dll")]static extern uint MsiViewExecute(uint view,uint record);
    [DllImport("msi.dll")]static extern uint MsiViewFetch(uint view,out uint record);
    [DllImport("msi.dll",CharSet=CharSet.Unicode,EntryPoint="MsiRecordGetStringW")]static extern uint MsiRecordGetString(uint record,uint field,StringBuilder value,ref uint length);
    [DllImport("msi.dll")]static extern uint MsiCloseHandle(uint handle);
    public void Dispose()=>http.Dispose();
}
