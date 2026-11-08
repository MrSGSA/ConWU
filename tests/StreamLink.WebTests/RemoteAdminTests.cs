using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Web;

internal static class RemoteAdminTests
{
    public static async Task Run(string root,Action<bool,string> check)
    {
        var config=RemoteAdminConfig.Create("https://manage.example.test/","test password 123456789");int calls=0;
        await using var panel=await WebPanel.StartRemote((_,_)=>{calls++;return Task.FromResult(new UiControlReply(true,"",null));},root,config,0);
        using var client=new HttpClient(new HttpClientHandler{UseCookies=false,AllowAutoRedirect=false}){BaseAddress=new Uri(panel.ListeningOrigin)};
        async Task<HttpResponseMessage> Send(HttpMethod method,string path,object? body=null,string? origin=null,string? cookie=null,string? csrf=null,string? host=null){
            var req=new HttpRequestMessage(method,path);req.Headers.Host=host??"manage.example.test";if(origin!=null)req.Headers.Add("Origin",origin);if(cookie!=null)req.Headers.Add("Cookie",cookie);if(csrf!=null)req.Headers.Add("X-StreamLink-CSRF",csrf);if(body!=null)req.Content=JsonContent.Create(body);return await client.SendAsync(req);
        }
        check((await Send(HttpMethod.Get,"/admin/login")).IsSuccessStatusCode,"remote login page on separate loopback listener");
        check((await Send(HttpMethod.Get,"/api/status")).StatusCode==HttpStatusCode.NotFound,"remote cannot serve root API");
        check((await Send(HttpMethod.Get,"/admin/api/status")).StatusCode==HttpStatusCode.Unauthorized,"remote status requires login");
        check((await Send(HttpMethod.Post,"/admin/api/login",new{password="test password 123456789"},"https://evil.test")).StatusCode==HttpStatusCode.Forbidden,"remote rejects cross-origin login");
        check((await Send(HttpMethod.Post,"/admin/api/login",new{password="bad password 12345"},config.Origin)).StatusCode==HttpStatusCode.Unauthorized,"remote rejects wrong password");
        var login=await Send(HttpMethod.Post,"/admin/api/login",new{password="test password 123456789"},config.Origin);var value=await login.Content.ReadFromJsonAsync<JsonElement>();string csrf=value.GetProperty("csrf").GetString()!;string set=login.Headers.GetValues("Set-Cookie").Single();string cookie=set.Split(';')[0];
        check(login.IsSuccessStatusCode&&set.Contains("secure",StringComparison.OrdinalIgnoreCase)&&set.Contains("httponly",StringComparison.OrdinalIgnoreCase)&&set.Contains("samesite=strict",StringComparison.OrdinalIgnoreCase)&&set.Contains("path=/admin/",StringComparison.OrdinalIgnoreCase),"remote cookie has secure isolation flags");
        check((await Send(HttpMethod.Get,"/admin/api/status",cookie:cookie)).IsSuccessStatusCode,"remote authenticated status");
        check((await Send(HttpMethod.Get,"/admin/api/status",cookie:cookie,host:"evil.test")).StatusCode==HttpStatusCode.Forbidden,"remote rejects forged host");
        check((await Send(HttpMethod.Post,"/admin/api/command",new{method="status",operationId=Guid.NewGuid()},config.Origin,cookie)).StatusCode==HttpStatusCode.Forbidden,"remote mutation requires CSRF");
        check((await Send(HttpMethod.Post,"/admin/api/command",new{method="status",operationId=Guid.NewGuid()},config.Origin,cookie,csrf)).IsSuccessStatusCode&&calls>=2,"remote authenticated command forwards");
        check((await Send(HttpMethod.Post,"/admin/api/logout",new{},config.Origin,cookie,csrf)).StatusCode==HttpStatusCode.NoContent,"remote logout succeeds");
        check((await Send(HttpMethod.Get,"/admin/api/status",cookie:cookie)).StatusCode==HttpStatusCode.Unauthorized,"remote logout revokes session");
        for(int i=0;i<3;i++)await Send(HttpMethod.Post,"/admin/api/login",new{password="wrong password 123"},config.Origin);
        check((await Send(HttpMethod.Post,"/admin/api/login",new{password="test password 123456789"},config.Origin)).StatusCode==HttpStatusCode.TooManyRequests,"remote login rate bounded");
    }
}
