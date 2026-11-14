using System.Net;
using System.Net.Sockets;
using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    sealed class ScriptedEntryHttp(Func<int,HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> send):HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>send(++Calls,request,token);
    }
    static async Task EntryResilience()
    {
        Task<IPAddress[]> Public(string _,CancellationToken ct)=>Task.FromResult(new[]{IPAddress.Parse("203.0.113.1")});
        Task<string[]> Empty(string _,CancellationToken ct)=>Task.FromResult(Array.Empty<string>());
        static HttpResponseMessage Ok()=>new(HttpStatusCode.OK){Content=new StringContent("203.0.113.5:44680")};
        using(var handler=new ScriptedEntryHttp((n,_,_)=>n==1?Task.FromException<HttpResponseMessage>(new HttpRequestException(HttpRequestError.ConnectionError,"synthetic token=must-not-leak")):Task.FromResult(Ok())))
        using(var resolver=new ExistingEntryResolver(Public,Empty,handler)){
            var result=(await resolver.Resolve([new(0,"https://example.com/entry?token=private")],"faketcp",default)).Single();
            Check(handler.Calls==2&&result.Endpoints.Length==1&&result.Attempts==2,"read-only subscription GET retries a transient connection failure once");
        }
        foreach(var code in new[]{HttpStatusCode.Forbidden,HttpStatusCode.Redirect,HttpStatusCode.Unauthorized}){
            using var handler=new ScriptedEntryHttp((_,_,_)=>Task.FromResult(new HttpResponseMessage(code)));
            using var resolver=new ExistingEntryResolver(Public,Empty,handler);
            var result=(await resolver.Resolve([new(0,"https://example.com/?token=private")],"faketcp",default)).Single();
            Check(handler.Calls==1&&result.Error.Contains(((int)code).ToString())&&!result.Error.Contains("private"),"non-transient HTTP "+(int)code+" is explicit, redacted and not retried");
        }
        foreach(var message in new[]{"entry report expired","节点 b 地址已过期"}){
            using var handler=new ScriptedEntryHttp((_,request,_)=>{
                Check(request.Headers.UserAgent.ToString().StartsWith("StreamLink/"),"subscription identifies its application to the HTTPS edge");
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable){Content=new StringContent(System.Text.Json.JsonSerializer.Serialize(new{ok=false,error=message,debug="token=must-not-leak"}),System.Text.Encoding.UTF8,"application/json")});
            });
            using var resolver=new ExistingEntryResolver(Public,Empty,handler);
            var result=(await resolver.Resolve([new(0,"https://example.com/?token=private")],"faketcp",default)).Single();
            Check(handler.Calls==1&&result.Error.Contains("上报已过期")&&result.Error.Contains("503")&&!result.Error.Contains("must-not-leak"),"expired reports explain the updater failure without retrying unchanged expired data or exposing debug fields");
        }
        using(var handler=new ScriptedEntryHttp((_,_,_)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable){Content=new StringContent("{\"error\":\"upstream token=must-not-leak\"}",System.Text.Encoding.UTF8,"application/json")})))
        using(var resolver=new ExistingEntryResolver(Public,Empty,handler)){
            var result=(await resolver.Resolve([new(0,"https://example.com/")],"faketcp",default)).Single();
            Check(handler.Calls==2&&result.Error.Contains("HTTP 503")&&!result.Error.Contains("must-not-leak"),"unknown provider errors retain bounded transient retry without echoing arbitrary response bodies");
        }
        using(var handler=new ScriptedEntryHttp((_,request,_)=>{request.Options.TryGetValue(ExistingEntryResolver.ProgressKey,out var progress);progress!.Stage="响应内容";return Task.FromException<HttpResponseMessage>(new OperationCanceledException("token=private"));}))
        using(var resolver=new ExistingEntryResolver(Public,Empty,handler)){
            var result=(await resolver.Resolve([new(0,"https://example.com/")],"faketcp",default)).Single();
            Check(handler.Calls==2&&result.Error.Contains("响应内容超时")&&!result.Error.Contains("private"),"timeout reports the failing phase and stops after two GETs");
        }
        var targets=new List<IPAddress>();var ipv4=IPAddress.Parse("203.0.113.2");var ipv6=IPAddress.Parse("2606:4700::1111");
        using(var resolver=new ExistingEntryResolver((_,_)=>Task.FromResult(new[]{ipv4,IPAddress.Parse("203.0.113.3"),ipv6}),Empty,connect:(endpoint,_)=>{
            targets.Add(endpoint.Address);return endpoint.Address.Equals(ipv4)?Task.FromException<Stream>(new SocketException((int)SocketError.NetworkUnreachable)):Task.FromResult<Stream>(new MemoryStream());
        })){
            using var stream=await resolver.ConnectPage(new("example.com",443),new(),default);
            Check(targets.SequenceEqual(new[]{ipv4,ipv6}),"pinned public connection alternates address families after first-address failure");
        }
        var late=new MemoryStream();var fast=new MemoryStream();bool abandoned=false;
        using(var resolver=new ExistingEntryResolver((_,_)=>Task.FromResult(new[]{ipv4,ipv6}),Empty,connect:async(endpoint,ct)=>{
            if(endpoint.Address.Equals(ipv6))return fast;
            try {await Task.Delay(Timeout.Infinite,ct);}catch(OperationCanceledException)when(ct.IsCancellationRequested){abandoned=true;}
            return late; // A connect completion racing cancellation still owns a stream.
        })){
            var progress=new ExistingEntryResolver.FetchProgress();var watch=System.Diagnostics.Stopwatch.StartNew();
            using var stream=await resolver.ConnectPage(new("example.com",443),progress,default);
            Check(ReferenceEquals(stream,fast)&&abandoned&&!late.CanRead&&watch.ElapsedMilliseconds<1500,"a blackholed first address does not delay a reachable second address and a late losing socket is joined and disposed");
            Check(progress.LastConnected!.Equals(ipv6),"the resolver remembers which address reached TCP before TLS or response failure");
        }
        targets.Clear();
        using(var resolver=new ExistingEntryResolver((_,_)=>Task.FromResult(new[]{ipv4,ipv6}),Empty,connect:(endpoint,_)=>{
            targets.Add(endpoint.Address);return Task.FromResult<Stream>(new MemoryStream());
        })){
            using var stream=await resolver.ConnectPage(new("example.com",443),new(){LastConnected=ipv4,Attempt=2},default);
            Check(targets.SequenceEqual(new[]{ipv6}),"a TLS or response retry prefers another validated public address instead of immediately repeating the stalled address");
        }
        int unsafeCalls=0;
        using(var resolver=new ExistingEntryResolver((_,_)=>Task.FromResult(new[]{ipv4,IPAddress.Loopback}),Empty,connect:(_,_)=>{unsafeCalls++;return Task.FromResult<Stream>(new MemoryStream());})){
            bool rejected=false;try{using var stream=await resolver.ConnectPage(new("example.com",443),new(),default);}catch(IOException){rejected=true;}
            Check(rejected&&unsafeCalls==0,"mixed public/private DNS answer is rejected before every socket attempt");
        }
        using(var stop=new CancellationTokenSource())
        using(var handler=new ScriptedEntryHttp((_,_,ct)=>{stop.Cancel();return Task.FromCanceled<HttpResponseMessage>(ct);}))
        using(var resolver=new ExistingEntryResolver(Public,Empty,handler)){
            bool cancelled=false;try{await resolver.Resolve([new(0,"https://example.com/")],"faketcp",stop.Token);}catch(OperationCanceledException){cancelled=true;}
            Check(cancelled&&handler.Calls==1,"caller cancellation never schedules a subscription retry");
        }
        await EntryConnectionReuse();
    }
}
