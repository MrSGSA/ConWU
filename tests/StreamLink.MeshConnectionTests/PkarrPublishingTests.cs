using System.Collections.Concurrent;
using System.Net;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    sealed class PublishingGateway:HttpMessageHandler
    {
        public readonly ConcurrentDictionary<string,byte[]> Packets=new();
        public int Count;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            string key=request.RequestUri!.AbsolutePath[1..];
            if(request.Method==HttpMethod.Put){Packets[key]=await request.Content!.ReadAsByteArrayAsync(token);Interlocked.Increment(ref Count);return new(HttpStatusCode.NoContent);}
            return Packets.TryGetValue(key,out var packet)?new(HttpStatusCode.OK){Content=new ByteArrayContent(packet)}:new(HttpStatusCode.NotFound);
        }
    }
    static async Task PkarrPublishingTests()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));string folder=Path.Combine(ProfileStore.Root,"pkarr-publication");
        using var gateway=new PublishingGateway();using var http=new HttpClient(gateway);
        PkarrClient Factory()=>new(http,["https://fixture.invalid"]);
        var mappings=new ConcurrentBag<Mapping>();
        IMapping Prepare(){var m=new Mapping();m.Change(new(IPAddress.Parse("203.0.113.54"),45460));mappings.Add(m);return m;}
        var host=new WorkspaceNode(folder,"Publishing host",pkarrFactory:Factory,mappingFactory:Prepare);bool closed=false;
        try{
            var c=(await host.State()).Configurations.Single();
            var enabled=await host.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",c.Id,c.Name,c.Revision,c.Settings with{DiscoveryMode="pkarr",ConnectionSource="custom",DirectMode=true,PkarrPublish=true})));Check(enabled.Ok,enabled.Error);
            var a=await host.Action("",new("create-direct"){Name="First publish",ConfigurationId=c.Id});Check(a.Ok,a.Error);
            var b=await host.Action("",new("create-direct"){Name="Second publish",ConfigurationId=c.Id});Check(b.Ok,b.Error);
            await Until(()=>gateway.Packets.Count==2,"two running network publishers deliver real signed PKARR packets to an injected gateway",18000);
            var state=await host.State();
            string[] sources=state.Networks.Select(n=>n.Status.Pkarr?.Source??"").ToArray();
            Check(sources.All(s=>s.StartsWith("pkarr://"))&&sources.Distinct().Count()==2,"each network has a distinct persistent discovery key even when settings are shared");
            foreach(var item in gateway.Packets){var packet=PkarrPacket.Read(item.Key,item.Value,DateTimeOffset.UtcNow);Check(packet.Announcement.Endpoints.Length>0,"background publication uses interoperable signed DNS packets");}
            Check(state.Configurations.Single().Settings.ExistingEntries.Single().Source==c.Settings.ExistingEntries.Single().Source,"publishing never rewrites the user's source configuration");
            Check(host.Probes>0&&gateway.Packets.All(p=>PkarrPacket.Read(p.Key,p.Value,DateTimeOffset.UtcNow).Announcement.Endpoints.Contains("203.0.113.54:45460")),"PKARR mode publishes autonomous prepared candidates rather than dormant third-party entries");
            int beforeChange=gateway.Count;
            foreach(var mapping in mappings)mapping.Change(new(IPAddress.Parse("203.0.113.2"),45200));
            await Until(()=>gateway.Count>=beforeChange+2,"autonomous mapping changes update the same PKARR records without editing settings",18000);
            Check(gateway.Packets.All(p=>PkarrPacket.Read(p.Key,p.Value,DateTimeOffset.UtcNow).Announcement.Endpoints.Contains("203.0.113.2:45200")),"updated announcements contain the new address");
            string firstId=a.Status!.SelectedNetworkId;
            var before=new ProfileStore(Path.Combine(host.Store.DirectoryPath,"networks",firstId),host.Store).LoadForMaintenance();
            var toggled=ProfileChanges.Copy(before);toggled.PkarrPublish=false;
            Check(ProfileChanges.Impact(before,toggled)!=ProfileChangeImpact.RestartNetwork,"PKARR enable/disable is independent of the active data path");
            var stale=ProfileChanges.Copy(before);stale.PkarrSeed="";stale.PkarrSequence=0;
            var restored=PairSettingsTransaction.SettingsOnly(before,stale);
            Check(restored.PkarrSeed==before.PkarrSeed&&restored.PkarrSequence==before.PkarrSequence,"settings rollback preserves the current discovery identity and monotonic publication sequence");
            await host.Worker.StopLocal();host.Dispose();closed=true;int beforeRestart=gateway.Count;
            using var restarted=new WorkspaceNode(folder,"ignored",reuseProfile:true,pkarrFactory:Factory,mappingFactory:Prepare);
            try{
                await Until(()=>gateway.Count>=beforeRestart+2&&restarted.NativeTarget!=null,"restart republishes both network discoveries",18000);
                var after=await restarted.State();
                Check(after.Networks.Select(n=>n.Status.Pkarr?.Source??"").Order().SequenceEqual(sources.Order()),"restart preserves publication keys instead of assigning new discovery identities");
                Check(gateway.Packets.Count==2,"restart updates the same records");
                int servers=restarted.Servers;var active=after.Configurations.Single();
                var off=await restarted.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",active.Id,active.Name,active.Revision,active.Settings with{DiscoveryMode="direct",PkarrPublish=false})));Check(off.Ok,off.Error);
                Check(restarted.Servers==servers,"disabling PKARR does not rebuild shared native receivers");
                Check((await restarted.State()).Networks.All(n=>n.Status.Settings?.PkarrPublish==false),"disabling publication is saved for each network");
            }finally{await restarted.Worker.StopLocal();}
        }finally{if(!closed){await host.Worker.StopLocal();host.Dispose();}}
        Console.WriteLine($"PASS {checks} integrated PKARR publisher checks; injected gateway, no public publication");
    }
}
