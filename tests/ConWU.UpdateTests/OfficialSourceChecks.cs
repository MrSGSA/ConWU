using System.Net;
using System.Text;
using System.Text.Json;
using StreamLink.Core;

static class OfficialSourceChecks
{
    public static async Task<int> Run()
    {
        int checks=0,calls=0;void Check(bool ok,string why){if(!ok)throw new Exception(why);checks++;Console.WriteLine("PASS "+why);}
        var package=new ReleaseUpdatePackage("ConWU-2.0.0-x64.msi",ReleaseUpdateClient.Repository+"/releases/download/v2.0.0/ConWU-2.0.0-x64.msi",4096,new string('a',64));
        var release=new ReleaseUpdateStatus("1.4.3","windows"){LatestVersion="2.0.0",ReleaseUrl=ReleaseUpdateClient.Repository+"/releases/tag/v2.0.0",UpdateAvailable=true,Package=package,DownloadSource="gitee"};
        using var http=new HttpClient(new Handler((request,_)=>{
            calls++;Check(request.Headers.Authorization==null&&request.RequestUri!.Host=="gitee.com","Gitee discovery uses only public repository metadata without publishing credentials");
            string json=calls==1?"{\"id\":41,\"tag_name\":\"v2.0.0\",\"prerelease\":false}":"[{\"id\":55,\"name\":\"ConWU-2.0.0-x64.msi\",\"size\":4096,\"browser_download_url\":\"https://evil.example/file\"}]";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(json,Encoding.UTF8,"application/json")});
        }));
        var url=await OfficialUpdateSources.Resolve(release,http,default);
        Check(calls==2&&url!.AbsoluteUri=="https://gitee.com/api/v5/repos/space4sgsa/ConWU/releases/41/attach_files/55/download","Gitee MSI lookup binds the selected tag and filename to the fixed official repository");
        Check(await OfficialUpdateSources.Resolve(release with{DownloadSource="github"},http,default)==null&&calls==2,"GitHub selection never contacts Gitee");
        foreach(string json in new[]{"[]","[{\"id\":55,\"name\":\"ConWU-2.0.0-windows-x64.zip\",\"size\":4096}]","[{\"id\":55,\"name\":\"ConWU-2.0.0-x64.msi\",\"size\":4095}]"}){
            using var parsed=JsonDocument.Parse(json);bool denied=false;try{OfficialUpdateSources.Parse(parsed.RootElement,41,package);}catch(IOException){denied=true;}Check(denied,"missing, ZIP-only or mismatched Gitee artifacts never substitute for the selected official MSI");
        }
        Check(!OfficialUpdateSources.Valid("https://evil.example")&&OfficialUpdateSources.Valid("gitee"),"download source selection accepts identifiers rather than arbitrary caller URLs");
        return checks;
    }
    sealed class Handler(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> send):HttpMessageHandler
    {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>send(request,token);}
}
