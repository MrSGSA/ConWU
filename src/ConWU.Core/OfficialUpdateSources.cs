using System.Net;
using System.Text.Json;

namespace StreamLink.Core;

public static class OfficialUpdateSources
{
    public const string GiteeRepository="https://gitee.com/space4sgsa/ConWU";
    public const string GiteeApi="https://gitee.com/api/v5/repos/space4sgsa/ConWU/releases/tags/";
    public static bool Valid(string source)=>source is "github" or "gitee";
    internal static async Task<Uri?> Resolve(ReleaseUpdateStatus release,HttpClient http,CancellationToken token)
    {
        if(!Valid(release.DownloadSource))throw new IOException("请选择 GitHub 或 Gitee 官方下载源");
        if(release.DownloadSource=="github")return null;
        var package=OfficialUpdatePackage.Validate(release,".msi");
        string prefix=ReleaseUpdateClient.Repository+"/releases/tag/";
        string tag=release.ReleaseUrl[prefix.Length..];
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromSeconds(20));
        using var response=await ReadResponse(http,GiteeApi+Uri.EscapeDataString(tag),timeout.Token);
        if(response.StatusCode==HttpStatusCode.NotFound)throw new IOException("Gitee 尚未同步此版本的 MSI，请选择 GitHub 或访问 Gitee 网站下载");
        if(!response.IsSuccessStatusCode)throw new IOException("暂时无法读取 Gitee 官方安装包，请稍后重试或选择 GitHub");
        using var releaseJson=await ReadJson(response,timeout.Token);
        var releaseNode=releaseJson.RootElement;
        if(releaseNode.GetProperty("tag_name").GetString()!=tag||releaseNode.TryGetProperty("prerelease",out var preview)&&preview.ValueKind==JsonValueKind.True)
            throw new IOException("Gitee 返回的版本与本次更新不符");
        long id=releaseNode.GetProperty("id").GetInt64();if(id<=0)throw new IOException("Gitee 发布身份无效");
        string files="https://gitee.com/api/v5/repos/space4sgsa/ConWU/releases/"+id+"/attach_files?per_page=100";
        using var attachments=await ReadResponse(http,files,timeout.Token);
        if(!attachments.IsSuccessStatusCode)throw new IOException("暂时无法读取 Gitee 安装包列表");
        using var assets=await ReadJson(attachments,timeout.Token);
        return Parse(assets.RootElement,id,package);
    }
    static async Task<HttpResponseMessage> ReadResponse(HttpClient http,string url,CancellationToken token)
    {
        using var request=new HttpRequestMessage(HttpMethod.Get,url);request.Headers.UserAgent.ParseAdd("ConWU-UpdateCheck/2");
        return await http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,token);
    }
    static async Task<JsonDocument> ReadJson(HttpResponseMessage response,CancellationToken token)
    {
        if(response.Content.Headers.ContentLength>262144)throw new IOException("Gitee 发布信息过大");
        await using var input=await response.Content.ReadAsStreamAsync(token);
        using var body=new MemoryStream();byte[] buffer=new byte[8192];
        while(true){int count=await input.ReadAsync(buffer,token);if(count==0)break;if(body.Length+count>262144)throw new IOException("Gitee 发布信息过大");body.Write(buffer,0,count);}
        return JsonDocument.Parse(body.ToArray(),new JsonDocumentOptions{MaxDepth=16});
    }
    internal static Uri Parse(JsonElement assets,long releaseId,ReleaseUpdatePackage package)
    {
        if(assets.ValueKind!=JsonValueKind.Array||assets.GetArrayLength()>128)throw new IOException("Gitee 安装包列表无效");
        var matches=assets.EnumerateArray().Where(a=>a.TryGetProperty("name",out var name)&&name.GetString()==package.Name).ToArray();
        if(matches.Length!=1)throw new IOException("Gitee 尚未同步此版本的 MSI，请选择 GitHub 或访问 Gitee 网站下载");
        var asset=matches[0];
        long id=asset.GetProperty("id").GetInt64();
        if(id<=0||releaseId<=0||asset.TryGetProperty("size",out var size)&&size.GetInt64()!=package.Bytes)throw new IOException("Gitee 安装包长度或身份与正式版不符");
        string expected=package.Url.Replace(ReleaseUpdateClient.Repository,GiteeRepository,StringComparison.Ordinal);
        if(asset.TryGetProperty("browser_download_url",out var browser)&&browser.GetString()==expected)return new(expected);
        return new("https://gitee.com/api/v5/repos/space4sgsa/ConWU/releases/"+releaseId+"/attach_files/"+id+"/download");
    }
}
