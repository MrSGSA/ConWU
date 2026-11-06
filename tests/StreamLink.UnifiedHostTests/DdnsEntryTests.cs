using System.Net;
using System.Text;
using StreamLink.Core;
using StreamLink.Service;

static class DdnsEntryTests
{
    public static async Task Run(Action<bool,string> check) {
        const string domain="conwu.example.test";
        var owner=MeshIdentity.Create("https://coord.example.test/","","faketcp");
        long utc=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string link=DdnsEntryLink.Create(domain,owner);
        var locator=DdnsEntryLink.Parse(link);
        check(locator.RecordName==DdnsAddressRecords.Name(domain,owner.Pair.Network,owner.Self.Device)&&locator.Key==owner.Self.SigningKey,"copied DDNS link pins the publishing member's public key and exact record");
        check(!link.Contains(owner.SigningPrivate)&&!link.Contains(owner.OwnerPrivate),"DDNS locator contains no private signing or enrollment credential");
        void Reject(string value) {
            try{DdnsEntryLink.Parse(value);}catch(FormatException){return;}
            throw new Exception("invalid DDNS link accepted");
        }
        Reject(link.Replace(domain,"user@"+domain));Reject(link.Replace(domain,domain+":443"));Reject(link+"&extra=1");Reject(link+"#extra");
        Reject(link.Replace("/"+owner.Self.Slot+"?","/0?"));Reject(link[..link.IndexOf("?key=")]+"?key=bad");
        check(true,"DDNS locators reject authority, slot, key and extra parameter ambiguity");
        ExistingEntryResolver.Validate([new(ExistingEntry.Network,link)]);
        var latest=DdnsAddressRecords.Create(owner,domain,"faketcp",["203.0.113.9:44680"],utc,180);
        string[] documents=[DdnsAddressRecords.Encode(latest)];bool unavailable=false;
        using var resolver=new ExistingEntryResolver((_,_)=>Task.FromResult(Array.Empty<IPAddress>()),
            (name,_)=>name!=locator.RecordName?throw new Exception("wrong DNS query"):unavailable?Task.FromException<string[]>(new IOException("fixture DNS failure")):Task.FromResult(documents),utcNow:()=>utc);
        async Task<EntryResolution> Resolve(string mode="faketcp")=>(await resolver.Resolve([new(ExistingEntry.Network,link)],mode,default)).Single();
        var first=await Resolve();
        check(first.Error.Length==0&&first.Endpoints.SequenceEqual(latest.Endpoints)&&first.ExpiresAt==latest.ExpiresAt,"DDNS link resolves signed endpoint and retains its absolute deadline");
        unavailable=true;var failure=await Resolve();
        check(EntryResolutionCache.Merge(failure,first,utc+20).Endpoints.Length==1,"temporary DNS failure can reuse only an unexpired authenticated hint");
        check(EntryResolutionCache.Merge(failure,first,utc+180).Endpoints.Length==0&&EntryResolutionCache.Current(first,utc+180).Endpoints.Length==0,"cached DNS failure and a long refresh interval cannot extend signed endpoint lifetime");
        unavailable=false;
        var changed=DdnsAddressRecords.Create(owner,domain,"faketcp",["203.0.113.10:44680"],utc+1,180);
        documents=[DdnsAddressRecords.Encode(changed)];var second=await Resolve();
        check(second.Endpoints.SequenceEqual(changed.Endpoints),"same saved DDNS link discovers changed IP and port");
        documents=[DdnsAddressRecords.Encode(latest)];var replay=await Resolve();
        check(replay.Error.Length>0&&!replay.AllowCached&&EntryResolutionCache.Merge(replay,second,utc).Endpoints.Length==0,"older DNS record cannot resurrect an old or cached endpoint");
        documents=[DdnsAddressRecords.Encode(changed with{Endpoints=["203.0.113.11:44680"]})];var tamper=await Resolve();
        check(tamper.Error.Length>0&&!tamper.AllowCached,"tampered DNS answers do not silently keep a previously cached dial target");
        var withdrawn=DdnsAddressRecords.Create(owner,domain,"faketcp",[],utc+2,180);
        documents=[DdnsAddressRecords.Encode(withdrawn)];var empty=await Resolve();
        check(empty.Error.Length==0&&empty.Endpoints.Length==0&&EntryResolutionCache.Merge(empty,second,utc).Endpoints.Length==0,"signed empty records withdraw dial targets immediately");
        documents=[DdnsAddressRecords.Encode(changed)];
        check((await Resolve("udp")).Error.Length>0,"DDNS never changes the selected transport protocol");
        utc+=190;documents=[DdnsAddressRecords.Encode(withdrawn)];
        check((await Resolve()).Error.Length>0,"expired DNS content is rejected even when recursive DNS keeps returning it");

        const string lucky="https://entries.example.test/latest#streamlink";
        var profile=new DeviceProfile{Mesh=owner,ConnectionSource="custom",ExistingEntries=[new(0,lucky),new(ExistingEntry.Network,"203.0.113.20:44680")]};
        string saved=System.Text.Json.JsonSerializer.Serialize(profile);
        check(MeshRunner.EntrySources(profile,owner).SequenceEqual([new ExistingEntry(0,lucky)]),"self-provided subscriptions are consumed in autonomous/coordinator mode without activating dormant remote settings");
        profile.ConnectionSource="existing";
        check(MeshRunner.EntrySources(profile,owner).Length==2&&profile.UsesExistingEntriesOnly,"existing mode retains all configured ingress hints and its strict no-autonomous policy");
        profile.ConnectionSource="custom";
        using var luckyResolver=new ExistingEntryResolver((_,_)=>Task.FromResult(Array.Empty<IPAddress>()),
            (_,_)=>Task.FromResult(new[]{"easytier=203.0.113.4:11010 streamlink=203.0.113.7:44680"}),new Page());
        var http=await luckyResolver.Resolve([new(0,lucky)],"faketcp",default);
        var txt=await luckyResolver.Resolve([new(0,"txt://entries.example.test#streamlink")],"faketcp",default);
        check(http.Single().Error.Length==0&&http.Single().Endpoints.SequenceEqual(txt.Single().Endpoints),"Lucky HTTPS and TXT share the existing tagged address format without a tool-specific adapter");
        var publicHints=MeshRunner.DdnsPublishable(null,http,utc);
        check(publicHints.SequenceEqual(["203.0.113.7:44680"]),"fresh Lucky source feeds the DDNS publisher in coordinator mode");
        var stale=http.Select(r=>r with{Error="source unavailable"}).ToArray();
        check(MeshRunner.DdnsPublishable(null,stale,utc).Length==0,"failed subscription cannot renew a stale address indefinitely through DDNS");
        check(MeshRunner.DdnsPublishable(null,http.Select(r=>r with{PeerSlot=ExistingEntry.Network}).ToArray(),utc).Length==0,"another device's configured network entry is never published as this device's ingress");
        var signed=DdnsAddressRecords.Create(owner,domain,"faketcp",publicHints,utc,180);documents=[DdnsAddressRecords.Encode(signed)];
        check((await Resolve()).Endpoints.SequenceEqual(publicHints),"source parsing, local publication selection, signing and stable-link reading form one usable pipeline");
        check(System.Text.Json.JsonSerializer.Serialize(profile)==saved,"dynamic discovery leaves every saved configuration field unchanged");
    }
    sealed class Page:HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token) {
            if(request.RequestUri!.Fragment.Length!=0)throw new Exception("tag selector leaked into HTTP request");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent("easytier=203.0.113.4:11010 streamlink=203.0.113.7:44680",Encoding.UTF8)});
        }
    }
}
