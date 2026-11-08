using System.Net;
using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task TaggedEntries()
    {
        string[] documents=["tcp://203.0.113.9:11010","v=spf1 -all","{unrelated verification}","streamlink=203.0.113.1:44680,edge.example.com:44681"," STREAMLINK=203.0.113.1:44680 "];
        var http=new TaggedEntryHttp {Body=string.Join('\n',documents)};
        string queried="";
        using var resolver=new ExistingEntryResolver((_,_)=>Task.FromResult(new[]{IPAddress.Parse("203.0.113.2")}),
            (host,_)=>{queried=host;return Task.FromResult(documents);},http);
        async Task<EntryResolution[]> Resolve()=>await resolver.Resolve([new(0,"txt://shared.example.com#streamlink"),new(0,"https://shared.example.com/connector?token=private#streamlink")],"faketcp",default);
        var results=await Resolve();
        Check(results.All(r=>r.Error==""&&r.Endpoints.SequenceEqual(new[]{"203.0.113.1:44680","203.0.113.2:44681"})),"TXT and HTTP isolate tagged entries across mixed records, ignore foreign data and deduplicate");
        Check(queried=="shared.example.com"&&http.RequestUri?.Fragment==""&&http.RequestUri.Query=="?token=private","strict selector is local: DNS name and HTTP path/query remain intact");
        var auto=await resolver.Resolve([new(0,"txt://shared.example.com"),new(0,"https://shared.example.com/connector")],"faketcp",default);
        Check(auto.All(r=>r.Endpoints.Length==2&&r.Error==""),"unqualified sources also prefer tagged records over old application endpoints");
        documents=["tcp://203.0.113.9:11010 streamlink=203.0.113.1:44680 other=203.0.113.9:4 streamlink=203.0.113.2:44681 tcp://203.0.113.9:11011"];http.Body=documents[0];
        Check((await Resolve()).All(r=>r.Endpoints.SequenceEqual(new[]{"203.0.113.1:44680","203.0.113.2:44681"})),"one shared TXT or HTTP line selects only tagged fields, including when a foreign endpoint follows a tag");
        documents=["tcp://203.0.113.9:11010"];http.Body=documents[0];
        results=await Resolve();
        Check(results.All(r=>r.Endpoints.Length==0&&r.Error.Contains("没有 streamlink=")&&!r.Error.Contains("private")),"missing tag fails closed for shared TXT/HTTPS instead of selecting EasyTier");
        var legacy=await resolver.Resolve([new(0,"txt://dedicated.example.com"),new(0,"https://dedicated.example.com/")],"faketcp",default);
        Check(legacy.All(r=>r.Endpoints.SequenceEqual(new[]{"203.0.113.9:11010"})),"dedicated unqualified plain subscriptions remain backward compatible");
        foreach(string invalid in new[]{"","not-an-address","udp://203.0.113.1:44680","https://127.0.0.1/secret"}) {
            documents=["tcp://203.0.113.9:11010","streamlink="+invalid];http.Body=string.Join('\n',documents);
            results=await Resolve();
            Check(results.All(r=>r.Endpoints.Length==0&&r.Error.Length>0),"empty, malformed, mismatched or recursive tagged entry never falls back to another app: "+(invalid.Length==0?"empty":invalid.Split(':')[0]));
        }
        foreach(string json in new[]{"[\"tcp://203.0.113.9:11010\",\"streamlink=203.0.113.1:44680\"]","{\"addresses\":[\"streamlink=203.0.113.1:44680\"]}","streamlink={\"endpoints\":[\"203.0.113.1:44680\"]}"}) {
            documents=[json];http.Body=json;results=await Resolve();
            Check(results.All(r=>r.Endpoints.SequenceEqual(new[]{"203.0.113.1:44680"})),"JSON lists and tagged JSON use the same selection policy");
        }
        documents=Enumerable.Range(1,9).Select(i=>$"streamlink=203.0.113.{i}:44680").ToArray();http.Body=string.Join('\n',documents);
        Check((await Resolve()).All(r=>r.Endpoints.Length==0&&r.Error.Contains("1–8")),"multiple tagged records retain the per-source endpoint bound");
        documents=Enumerable.Repeat("streamlink=203.0.113.1:44680",9).ToArray();http.Body=string.Join('\n',documents);
        Check((await Resolve()).All(r=>r.Endpoints.Length==1),"duplicate tagged records do not consume endpoint slots");
        documents=["streamlink=203.0.113.3:44680"];http.Body=documents[0];
        Check((await Resolve()).All(r=>r.Endpoints.SequenceEqual(new[]{"203.0.113.3:44680"})),"changed tagged subscriptions resolve fresh endpoints after a previous failure");
        ExistingEntryResolver.Validate([new(0,"txt://shared.example.com#other"),new(0,"https://shared.example.com/#other")]);
        Check(true,"custom host labels are accepted by both TXT and HTTPS sources");
        foreach(string bad in new[]{"txt://shared.example.com/streamlink","txt://shared.example.com#1other","https://shared.example.com/#other.tag","https://shared.example.com/#other#streamlink"}) {
            bool rejected=false;try{ExistingEntryResolver.Validate([new(0,bad)]);}catch(FormatException){rejected=true;}
            Check(rejected,"unsupported selectors are rejected without an outbound request");
        }
    }
    sealed class TaggedEntryHttp:HttpMessageHandler
    {
        public string Body="";
        public Uri? RequestUri;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token) {
            RequestUri=request.RequestUri;return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(Body)});
        }
    }
}
