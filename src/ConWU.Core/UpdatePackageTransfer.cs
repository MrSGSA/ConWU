using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

internal sealed record UpdateDownloadPolicy(TimeSpan HeaderTimeout,TimeSpan IdleTimeout,TimeSpan RetryDelay,int Attempts)
{
    public static UpdateDownloadPolicy Default {get;}=new(TimeSpan.FromSeconds(30),TimeSpan.FromSeconds(45),TimeSpan.FromSeconds(2),5);
}

// A slow transfer may keep making progress for longer than fifteen minutes.
// Only a stalled request is timed out. Retry from the canonical URL so an
// expired, signed CDN redirect is never persisted as the download's identity.
internal static class UpdatePackageTransfer
{
    sealed record Resume(string Url,long Bytes,string Sha256);
    sealed class InvalidPackage(string message):IOException(message);
    sealed class StorageFailure(string message,Exception inner):IOException(message,inner);

    internal static async Task Download(ReleaseUpdatePackage package,string target,Action<long,long> progress,
        CancellationToken token,HttpClient client,UpdateDownloadPolicy? policy=null)
    {
        policy??=UpdateDownloadPolicy.Default;
        if(package.Bytes is <1024 or >1_073_741_824||package.Sha256.Length!=64||!package.Sha256.All(char.IsAsciiHexDigit)||
            !Uri.TryCreate(package.Url,UriKind.Absolute,out var canonical)||
            !package.Url.StartsWith(ReleaseUpdateClient.Repository+"/releases/download/",StringComparison.Ordinal))
            throw new IOException("更新包的来源、长度或校验信息无效");
        ValidateUrl(canonical);
        string partial=target+".partial",metadata=partial+".json";
        var identity=new Resume(package.Url,package.Bytes,package.Sha256.ToUpperInvariant());
        CheckFile(target);CheckFile(partial);CheckFile(metadata);CheckFile(metadata+".tmp");
        if(File.Exists(target)){
            await using var existing=File.OpenRead(target);
            if(existing.Length!=package.Bytes||!Convert.ToHexString(await SHA256.HashDataAsync(existing,token)).Equals(package.Sha256,StringComparison.OrdinalIgnoreCase))
                throw new IOException("现有下载文件与本次更新不符");
            progress(package.Bytes,package.Bytes);return;
        }
        bool invalid=false;
        try{
            await using(var output=new FileStream(partial,FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None,131072,FileOptions.Asynchronous|FileOptions.SequentialScan)){
                Resume? saved=null;
                if(File.Exists(metadata)&&new FileInfo(metadata).Length<=4096)
                    try{saved=JsonSerializer.Deserialize<Resume>(await File.ReadAllTextAsync(metadata,token));}catch(JsonException){}
                if(saved!=identity||output.Length>package.Bytes)output.SetLength(0);
                await File.WriteAllTextAsync(metadata+".tmp",JsonSerializer.Serialize(identity),token);
                File.Move(metadata+".tmp",metadata,true);
                output.Position=output.Length;progress(output.Length,package.Bytes);
                int failures=0;long reportedAt=Environment.TickCount64;
                byte[] buffer=new byte[131072];
                while(output.Length<package.Bytes){
                    token.ThrowIfCancellationRequested();long start=output.Length,previousProgress=start;
                    try{
                        using var response=await Open(client,canonical,start,policy,token);
                        if(response.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.RequestTimeout or HttpStatusCode.Forbidden or HttpStatusCode.Gone||
                            (int)response.StatusCode>=500)throw new HttpRequestException("下载服务暂时繁忙");
                        if(response.StatusCode is not(HttpStatusCode.OK or HttpStatusCode.PartialContent))
                            throw new InvalidPackage("更新下载地址暂不可用，请重新检查更新后重试");
                        if(response.Content.Headers.ContentEncoding.Any(value=>!value.Equals("identity",StringComparison.OrdinalIgnoreCase)))throw new InvalidPackage("更新包返回了不支持的内容编码");
                        long expected;
                        if(response.StatusCode==HttpStatusCode.PartialContent){
                            var range=response.Content.Headers.ContentRange;
                            if(range?.Unit!="bytes"||range.From!=start||range.Length!=package.Bytes||range.To is not {} last||last<start||last>=package.Bytes)
                                throw new InvalidPackage("服务器返回的续传范围与安装包不符");
                            expected=last-start+1;
                        }else expected=package.Bytes;
                        if(response.Content.Headers.ContentLength is {} length&&length!=expected)
                            throw new InvalidPackage("安装包长度与正式发布信息不符");
                        // Some servers ignore Range. Restart rather than append
                        // another full response to an already downloaded prefix.
                        if(response.StatusCode==HttpStatusCode.OK&&start>0){output.SetLength(0);output.Position=0;progress(0,package.Bytes);start=0;}
                        long received=0;
                        await using var input=await response.Content.ReadAsStreamAsync(token);
                        while(true){
                            int count;
                            using(var idle=CancellationTokenSource.CreateLinkedTokenSource(token)){
                                idle.CancelAfter(policy.IdleTimeout);
                                try{count=await input.ReadAsync(buffer,idle.Token);idle.Token.ThrowIfCancellationRequested();}
                                catch(OperationCanceledException)when(!token.IsCancellationRequested){throw new IOException("下载连接长时间没有收到数据");}
                            }
                            if(count==0)break;
                            received+=count;
                            if(received>expected||output.Position+count>package.Bytes)throw new InvalidPackage("安装包超过正式发布的预期长度");
                            try{await output.WriteAsync(buffer.AsMemory(0,count),token);}
                            catch(IOException error){throw new StorageFailure("无法写入更新缓存，请检查磁盘空间和权限",error);}
                            long now=Environment.TickCount64;
                            if(now-reportedAt>=200||output.Length==package.Bytes){progress(output.Length,package.Bytes);reportedAt=now;}
                        }
                        if(received!=expected)throw new IOException("下载连接提前结束");
                        failures=0;
                    }catch(Exception error)when(error is not(InvalidPackage or StorageFailure)&&!token.IsCancellationRequested&&
                        error is IOException or HttpRequestException or OperationCanceledException){
                        await output.FlushAsync(token);progress(output.Length,package.Bytes);
                        if(output.Length>previousProgress)failures=0;
                        if(++failures>=policy.Attempts)throw new IOException("更新下载多次中断，已保留 "+(output.Length/1048576d).ToString("F1")+" MB；再次下载会从已有进度继续，当前网络保持运行",error);
                        await Task.Delay(policy.RetryDelay,token);
                    }
                }
                await output.FlushAsync(token);output.Position=0;
                if(!Convert.ToHexString(await SHA256.HashDataAsync(output,token)).Equals(package.Sha256,StringComparison.OrdinalIgnoreCase))
                    throw new InvalidPackage("安装包完整校验失败，已丢弃错误下载；当前网络保持运行");
                output.Flush(true);token.ThrowIfCancellationRequested();
            }
            File.Move(partial,target,false);File.Delete(metadata);progress(package.Bytes,package.Bytes);
        }catch(InvalidPackage){invalid=true;throw;}
        finally{
            // Network errors and cancellation preserve the prefix. Untrusted
            // contents can never be resumed or offered to the OS installer.
            if(invalid){if(File.Exists(partial))File.Delete(partial);if(File.Exists(metadata))File.Delete(metadata);}
            if(File.Exists(metadata+".tmp"))File.Delete(metadata+".tmp");
        }
    }
    static async Task<HttpResponseMessage> Open(HttpClient client,Uri canonical,long offset,UpdateDownloadPolicy policy,CancellationToken token)
    {
        Uri url=canonical;
        for(int hop=0;hop<6;hop++){
            ValidateUrl(url);
            using var request=new HttpRequestMessage(HttpMethod.Get,url);
            request.Headers.UserAgent.ParseAdd("ConWU-LocalUpdate/2");request.Headers.AcceptEncoding.ParseAdd("identity");
            if(offset>0)request.Headers.Range=new RangeHeaderValue(offset,null);
            using var headers=CancellationTokenSource.CreateLinkedTokenSource(token);headers.CancelAfter(policy.HeaderTimeout);
            HttpResponseMessage response;
            try{response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,headers.Token);}
            catch(OperationCanceledException)when(!token.IsCancellationRequested){throw new IOException("连接更新下载源超时");}
            if((int)response.StatusCode is >=300 and <=399){
                var location=response.Headers.Location;response.Dispose();
                if(location==null)throw new InvalidPackage("更新下载重定向无效");
                url=location.IsAbsoluteUri?location:new(url,location);continue;
            }
            return response;
        }
        throw new InvalidPackage("更新下载重定向次数过多");
    }
    static void ValidateUrl(Uri url)
    {
        if(url.Scheme!="https"||url.UserInfo.Length>0||!url.IsDefaultPort||
            url.Host is not("github.com" or "release-assets.githubusercontent.com" or "objects.githubusercontent.com"))
            throw new InvalidPackage("安装包下载跳转到未认可的来源");
    }
    static void CheckFile(string path)
    {
        if(File.Exists(path)&&(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)
            throw new IOException("更新缓存不能是链接");
    }
}
