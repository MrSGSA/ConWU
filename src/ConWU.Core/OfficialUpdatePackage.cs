using System.Security.Cryptography;

namespace StreamLink.Core;

// Used by clients that hand a complete local package to the OS installer.
// The caller still verifies its platform's package identity and signing key.
public static class OfficialUpdatePackage
{
    public static ReleaseUpdatePackage Validate(ReleaseUpdateStatus release,string extension)
    {
        var package=release.Package??throw new IOException("没有适合本机的安装包");
        string prefix=ReleaseUpdateClient.Repository+"/releases/tag/";
        string tag=release.ReleaseUrl.StartsWith(prefix,StringComparison.Ordinal)?release.ReleaseUrl[prefix.Length..]:"";
        if(!release.UpdateAvailable||!ReleaseVersion.TryParse(release.LatestVersion,out _)||tag!=release.LatestVersion&&tag!="v"+release.LatestVersion||
            !package.Name.StartsWith("ConWU-"+release.LatestVersion+"-",StringComparison.Ordinal)||!package.Name.EndsWith(extension,StringComparison.Ordinal)||
            package.Name.Any(c=>char.IsControl(c)||c is '/' or '\\')||package.Url!=ReleaseUpdateClient.Repository+"/releases/download/"+Uri.EscapeDataString(tag)+"/"+Uri.EscapeDataString(package.Name)||
            package.Bytes is <1024 or >1_073_741_824||package.Sha256.Length!=64||!package.Sha256.All(char.IsAsciiHexDigit))throw new IOException("安装包的来源、版本或校验信息不完整");
        return package;
    }
    public static async Task Download(ReleaseUpdatePackage package,string target,Action<long,long> progress,CancellationToken token,HttpClient? client=null)
    {
        bool owns=client==null;
        client??=new(new SocketsHttpHandler{AllowAutoRedirect=false,UseCookies=false,ConnectTimeout=TimeSpan.FromSeconds(10)}){Timeout=Timeout.InfiniteTimeSpan};
        string partial=target+".partial";HttpResponseMessage? response=null;
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(TimeSpan.FromMinutes(15));
        try{
            Uri url=new(package.Url);
            for(int hops=0;hops<6;hops++){
                if(url.Scheme!="https"||url.UserInfo.Length>0||!url.IsDefaultPort||url.Host is not("github.com" or "release-assets.githubusercontent.com" or "objects.githubusercontent.com"))throw new IOException("安装包下载跳转到未认可的来源");
                using var request=new HttpRequestMessage(HttpMethod.Get,url);request.Headers.UserAgent.ParseAdd("ConWU-LocalUpdate/1");
                response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,deadline.Token);
                if((int)response.StatusCode is >=300 and <=399){var next=response.Headers.Location??throw new IOException("更新重定向无效");url=next.IsAbsoluteUri?next:new(url,next);response.Dispose();response=null;continue;}
                break;
            }
            if(response?.IsSuccessStatusCode!=true)throw new IOException("安装包下载暂不可用");
            if(response.Content.Headers.ContentLength is {} length&&length!=package.Bytes)throw new IOException("安装包长度与发布信息不符");
            await using(var input=await response.Content.ReadAsStreamAsync(deadline.Token))await using(var output=new FileStream(partial,FileMode.CreateNew,FileAccess.Write,FileShare.None,131072,FileOptions.Asynchronous)){
                byte[] buffer=new byte[131072];long received=0;using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                while(true){int count=await input.ReadAsync(buffer,deadline.Token);if(count==0)break;received+=count;if(received>package.Bytes)throw new IOException("安装包超过预期长度");hash.AppendData(buffer,0,count);await output.WriteAsync(buffer.AsMemory(0,count),deadline.Token);progress(received,package.Bytes);}
                await output.FlushAsync(deadline.Token);
                if(received!=package.Bytes||!Convert.ToHexString(hash.GetHashAndReset()).Equals(package.Sha256,StringComparison.OrdinalIgnoreCase))throw new IOException("安装包下载不完整或校验失败，现有网络保持运行");
            }
            File.Move(partial,target,false);
        }finally{response?.Dispose();if(owns)client.Dispose();if(File.Exists(partial))File.Delete(partial);}
    }
}
