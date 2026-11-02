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
    }
}
