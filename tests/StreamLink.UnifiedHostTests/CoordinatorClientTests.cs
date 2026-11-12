using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using StreamLink.Core;
using StreamLink.Discovery;

static class CoordinatorClientTests
{
    sealed class Clock : TimeProvider
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        long tick;
        public override DateTimeOffset GetUtcNow() => now;
        public override long GetTimestamp() => tick;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public void Advance(TimeSpan duration) { now += duration; tick += duration.Ticks; }
    }
    public static async Task Run(Action<bool,string> check)
    {
        var clock = new Clock();
        var activity = new CoordinatorClients(clock);
        activity.Observe("device","Host","pair:room","配对中");
        activity.Observe("device","","first-network","网络发现");
        activity.Observe("device","","second-network","网络发现");
        check(activity.Snapshot() is [{Name:"Host",Networks:2}],"coordinator activity combines the same device across networks and retains its observed name");
        activity.Observe("device","Renamed","second-network","网络发现");
        check(activity.Snapshot() is [{Name:"Renamed",Phase:"网络发现"}],"the newest device name and purpose win even when observations share a clock tick");
        activity.RemoveScope("pair:room");
        check(activity.Snapshot() is [{Networks:2}],"closing a pairing room retains independently active discovery sessions");
        clock.Advance(TimeSpan.FromMinutes(3));
        check(activity.Snapshot().Length==0,"inactive coordinator clients expire using monotonic time");

        string root=Path.Combine(Path.GetTempPath(),"conwu-client-view-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        await using var host=CoordinationHost.Create(new(root,"http://127.0.0.1:0"));
        await host.Start();
        using var http=new HttpClient(new HttpClientHandler {UseProxy=false}) {BaseAddress=new(host.Addresses.Single())};
        await http.GetAsync("health");
        check(host.Clients.Length==0,"health probes do not appear as coordinated devices");
        using var pair=new PairKeyExchange(NodeIdentityProof.GeneratePrivate());
        var create=await http.PostAsJsonAsync("v2/pair",new PairRoomCreate(pair.Commitment,"Pair device"){Identity=pair.Identity});
        var ticket=(await create.Content.ReadFromJsonAsync<PairRoomTicket>())!;
        async Task<HttpStatusCode> Owner(string token)
        {
            using var request=new HttpRequestMessage(HttpMethod.Get,"v2/pair/"+ticket.Room+"/owner");
            request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",token);
            using var response=await http.SendAsync(request);
            return response.StatusCode;
        }
        check(await Owner(new string('A',64))==HttpStatusCode.Unauthorized&&host.Clients.Length==0,"unauthorized pairing polls cannot create coordinator activity");
        check(await Owner(ticket.Token)==HttpStatusCode.OK&&host.Clients is [{Name:"Pair device",Phase:"配对中"}],"authenticated pairing activity reaches the integrated host snapshot");
        var owner=MeshIdentity.Create("https://example.test/","","faketcp",deviceId:pair.Identity!.DeviceId);
        async Task<HttpStatusCode> Put(string path,object value,string token)
        {
            using var request=new HttpRequestMessage(HttpMethod.Put,path){Content=JsonContent.Create(value)};
            request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",token);
            using var response=await http.SendAsync(request);
            return response.StatusCode;
        }
        check(await Put("v3/mesh/"+owner.Pair.Network+"/directory",owner.Directory!,owner.Pair.Auth)==HttpStatusCode.NoContent,"coordinator client fixture registers an authenticated network");
        var envelope=MeshMetadata.Seal(owner,new(owner.Self.Slot,owner.Self.Device,1,DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeSeconds(),"127.0.0.1:44680","encrypted name"));
        string publish="v3/mesh/"+owner.Pair.Network+"/nodes/"+owner.Self.Slot;
        check(await Put(publish,envelope,new string('B',64))==HttpStatusCode.Unauthorized&&host.Clients is [{Networks:0}],"rejected discovery requests do not invent an active network");
        check(await Put(publish,envelope,owner.Pair.Auth)==HttpStatusCode.NoContent&&host.Clients is [{Name:"Pair device",Networks:1,Phase:"网络发现"}],"signed discovery publication updates the same real device without exposing encrypted metadata");
        using var close=new HttpRequestMessage(HttpMethod.Delete,"v2/pair/"+ticket.Room);
        close.Headers.Authorization=new AuthenticationHeaderValue("Bearer",ticket.Token);
        await http.SendAsync(close);
        check(host.Clients is [{Networks:1}],"closing pairing preserves the authenticated device's network activity");
    }
}
