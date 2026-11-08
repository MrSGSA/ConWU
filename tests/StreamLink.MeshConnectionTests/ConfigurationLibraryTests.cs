using System.Net;
using System.Security.Principal;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    static async Task ConfigurationLibrary()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var store=new ProfileStore();string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        store.Save(new DeviceProfile{ConnectionSource="existing",DirectMode=true,ListenPort=45420,SourcePort=45421});
        int opened=0,probes=0;var adapters=new List<MemoryAdapter>();
        var runtime=new MeshRuntimeServices(m=>new DirectMeshDiscovery(m),_=>{Interlocked.Increment(ref opened);var a=new MemoryAdapter();lock(adapters)adapters.Add(a);return Task.FromResult<IPacketAdapter>(a);},
            (_,_,_)=>{Interlocked.Increment(ref probes);throw new IOException("autonomous probe forbidden");},r=>new StubTransport(null),
            (_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},Path.Combine(store.DirectoryPath,"sessions")){
            Candidates=(_,_,_,_)=>throw new IOException("autonomous candidates forbidden"),NetworkWake=()=>new MeshNetworkWake(false),ResolveEntries=(entries,mode,ct)=>Task.FromResult(entries.Select((e,i)=>new EntryResolution(e.PeerSlot,i,"TXT",[],"offline test source")).ToArray())
        };
        using(var worker=new ControlWorker(runtime)){
            worker.EnablePairNetworks();worker.StartLocal();
            async Task<UiControlReply> Ui(UiControlRequest request){request=request.OperationId==Guid.Empty?request with{OperationId=Guid.NewGuid()}:request;var reply=await worker.HandleUi(request,sid,default);while(reply.Operation is {Completed:false}){await Task.Delay(20);reply=await worker.HandleUi(new("status",OperationId:request.OperationId){NetworkId=reply.Status?.SelectedNetworkId??request.NetworkId},sid,default);}return reply;}
            var initial=(await Ui(new("status"))).Status!;var config=initial.Configurations.Single();
            Check(config.Networks.Length==0&&opened==0,"unassociated saved configuration starts no adapter or autonomous discovery");
            Task<UiControlReply> Create(string name)=>Ui(new("network",Network:new("create-direct"){Name=name,ConfigurationId=config.Id}));
            var first=await Create("主机—笔记本");Check(first.Ok,first.Error);string firstId=first.Status!.SelectedNetworkId;
            var second=await Create("主机—另一台电脑");Check(second.Ok,second.Error);string secondId=second.Status!.SelectedNetworkId;
            await Until(()=>Volatile.Read(ref opened)==2,"two independent configuration users open their own adapters");
            var both=(await Ui(new("status"))).Status!;config=both.Configurations.Single();
            Check(config.Networks.Length==2&&both.Networks.All(n=>n.ConfigurationId==config.Id),"networks explicitly reference the same saved configuration");
            Check(both.Networks.Select(n=>n.Status.Settings!.SourcePort).Distinct().Count()==2&&both.Networks.Select(n=>n.Status.NetworkId).Distinct().Count()==2,"shared configuration keeps source allocation and network identity separate");
            var changed=config.Settings with{EntryRefreshSeconds=120,ExistingEntries=[new(0,"txt://entry.example.com#streamlink1")]};
            var saved=await Ui(new("configuration",Configuration:new("save",config.Id,"家中入口",config.Revision,changed,true)));Check(saved.Ok,saved.Error);
            config=saved.Status!.Configurations.Single();
            Check(config.Revision==2&&config.Networks.All(n=>n.State=="applied")&&saved.Status.Networks.All(n=>n.Status.Settings!.EntryRefreshSeconds==120),"saving a shared configuration updates every associated network and applied revision");
            var stale=await Ui(new("configuration",Configuration:new("save",config.Id,"旧窗口",1,changed,true)));
            Check(!stale.Ok&&stale.Error.Contains("其他窗口")&&stale.Status!.Configurations.Single().Revision==2,"stale editor cannot overwrite shared configuration");
            var identities=saved.Status.Networks.ToDictionary(n=>n.Id,n=>n.Status.NetworkId);
            var ports=config.Settings with{ListenPort=45440,SourcePort=45441};
            var unconfirmed=await Ui(new("configuration",Configuration:new("save",config.Id,config.Name,config.Revision,ports)));
            Check(!unconfirmed.Ok&&unconfirmed.Status!.Configurations.Single().Revision==config.Revision&&unconfirmed.Status.Networks.All(n=>n.Status.Settings!.ListenPort==45420),"unconfirmed shared restart changes no saved setting or active listener");
            var reconfigured=await Ui(new("configuration",Configuration:new("save",config.Id,config.Name,config.Revision,ports,true)));Check(reconfigured.Ok,reconfigured.Error);config=reconfigured.Status!.Configurations.Single();
            Check(reconfigured.Status.Networks.All(n=>n.Status.Settings!.ListenPort==45440&&identities[n.Id]==n.Status.NetworkId)&&reconfigured.Status.Networks.Select(n=>n.Status.Settings!.SourcePort).Distinct().Count()==2,"shared listener changes release old consumers together and preserve network identities and separate source ports");
            var pause=await Ui(new("stop"){NetworkId=secondId});Check(pause.Ok,pause.Error);
            var paused=(await Ui(new("status"))).Status!;Check(paused.Configurations.Single().Networks.Length==2,"stopped network is still associated with its saved configuration");
            var inUse=await Ui(new("configuration",Configuration:new("delete",config.Id,ExpectedRevision:config.Revision)));
            Check(!inUse.Ok&&inUse.Error.Contains("主机—"),"in-use configuration deletion lists its associated networks");
            var copy=await Ui(new("configuration",Configuration:new("copy",config.Id,"独立配置",config.Revision)));Check(copy.Ok,copy.Error);
            var copied=copy.Status!.Configurations.Single(c=>c.Id==copy.ConfigurationId);
            Check(copied.Id!=config.Id&&copied.Networks.Length==0&&copy.Status.Networks.Length==2,"explicit copy creates only settings with no identities or network links");
            var assign=await Ui(new("configuration",Configuration:new("assign",copied.Id,ExpectedRevision:copied.Revision,ConfirmReconnect:true)){NetworkId=secondId});Check(assign.Ok,assign.Error);
            Check(assign.Status!.Configurations.All(c=>c.Networks.Length==1),"changing one network configuration does not reassign other users");
            var independent=await Ui(new("configuration",Configuration:new("save",copied.Id,copied.Name,copied.Revision,copied.Settings with{EntryRefreshSeconds=240},true)));Check(independent.Ok,independent.Error);
            Check(independent.Status!.Networks.Single(n=>n.Id==firstId).Status.Settings!.EntryRefreshSeconds==120&&independent.Status.Networks.Single(n=>n.Id==secondId).Status.Settings!.EntryRefreshSeconds==240,"independent configurations do not overwrite each other");
            var close=await Ui(new("network",Network:new("forget-network",ExpectedNetwork:independent.Status.Networks.Single(n=>n.Id==firstId).Status.NetworkId,ConfirmReplace:true)){NetworkId=firstId});Check(close.Ok,close.Error);
            Check(close.Status!.Networks.Length==1&&close.Status.Configurations.Single(c=>c.Id==config.Id).Networks.Length==0,"local exit removes the association and preserves the saved configuration");
            var staleView=await Ui(new("status"){NetworkId=firstId});
            Check(staleView.Ok&&staleView.Status!.SelectedNetworkId.Length==0&&staleView.Status.Networks.Length==1,"late status poll for a removed network returns the healthy workspace instead of a false backend failure");
            var unauthorized=await worker.HandleUi(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("delete",config.Id,ExpectedRevision:2)),"S-1-5-18-invalid",default);
            Check(!unauthorized.Ok&&unauthorized.Status==null,"configuration library mutations require the authorized local identity");
            var competing=await Task.WhenAll(Enumerable.Range(0,2).Select(i=>Ui(new("configuration",Configuration:new("save",config.Id,"竞争"+i,config.Revision,changed,true)))));
            Check(competing.Count(r=>r.Ok)==1,"concurrent saves serialize and enforce the expected configuration revision");
            Check(probes==0,"existing-entry configurations never launch autonomous probing");
            await worker.StopLocal();
        }
        var remainingInfo=Directory.EnumerateFiles(Path.Combine(store.DirectoryPath,"networks"),"network-info.json",SearchOption.AllDirectories)
            .Select(path=>(Path:path,Info:System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(path))!)).Single(p=>p.Info["Removed"]?.GetValue<bool>()!=true);
        remainingInfo.Info["AppliedConfigurationRevision"]=0;File.WriteAllText(remainingInfo.Path,remainingInfo.Info.ToJsonString());
        using(var restarted=new ControlWorker(runtime)){
            restarted.EnablePairNetworks();var status=(await restarted.HandleUi(new("status"),sid,default)).Status!;
            Check(status.Networks.Length==1&&status.Configurations.Length==2&&status.Networks.Single().ConfigurationId==status.Configurations.Single(c=>c.Name=="独立配置").Id,"restart preserves independent settings and the exact network reference");
            Check(status.Configurations.Single(c=>c.Name=="独立配置").Settings.EntryRefreshSeconds==240,"restart does not replace saved settings with runtime state");
            Check(status.Networks.Single().AppliedConfigurationRevision==status.Configurations.Single(c=>c.Name=="独立配置").Revision&&!status.Networks.Single().Status.NetworkEnabled,"startup finishes an interrupted configuration application without starting a paused network");
            await restarted.StopLocal();
        }
        using var resolver=new ExistingEntryResolver((host,ct)=>Task.FromResult(new[]{IPAddress.Parse("203.0.113.42")}),
            (host,ct)=>Task.FromResult(new[]{"streamlink1=203.0.113.42:45420 streamlink2=203.0.113.43:45430"}));
        var selected=await resolver.Resolve([new(-1,"entry.example.com#streamlink2")],"faketcp",default);
        Check(selected.Single().Endpoints.SequenceEqual(new[]{"203.0.113.43:45430"}),"bare domain and exact selector choose only the intended host source");
        Check(ExistingEntryResolver.ParseDocuments(["streamlink1=203.0.113.42:45420\nstreamlink10=203.0.113.43:45430"],true,"streamlink1").SequenceEqual(new[]{"203.0.113.42:45420"}),"selector prefix collision cannot select another host");
        try{ExistingEntryResolver.ParseDocuments(["streamlink2=203.0.113.42:45420"],true,"streamlink1");throw new Exception("missing selector accepted");}catch(FormatException){Check(true,"missing selector fails without falling back to a different host");}
        using var documents=new SelectorDocuments();
        using var https=new ExistingEntryResolver((host,ct)=>Task.FromResult(new[]{IPAddress.Parse("203.0.113.42")}),(_,_)=>Task.FromResult(Array.Empty<string>()),documents);
        var httpsSelected=await https.Resolve([new(-1,"https://entry.example.com/current?token=example#streamlink2")],"faketcp",default);
        Check(httpsSelected.Single().Endpoints.SequenceEqual(new[]{"203.0.113.43:45430"})&&documents.Last!.Fragment.Length==0&&documents.Last.Query=="?token=example","HTTPS selects an exact label while keeping read credentials and omitting the fragment from the HTTP request");
        var missing=await https.Resolve([new(-1,"https://entry.example.com/current#missing")],"faketcp",default);
        Check(missing.Single().Endpoints.Length==0&&missing.Single().Error.Contains("missing="),"missing HTTPS selector cannot fall back to another host");
        Check(typeof(DeviceProfile).Assembly.GetType("StreamLink.Core.CloudflareDdnsClient")==null,"product assembly contains no Cloudflare DNS writer");
        var legacyStore=new ProfileStore(Path.Combine(store.DirectoryPath,"removed-ddns"));
        var legacy=new DeviceProfile{Ddns=new(true,"entry.example.com",new string('a',32),true),CloudflareDdnsToken=new string('A',30),ExistingEntries=[new(0,"conwu-ddns://retired"),new(0,"https://entry.example.com/current#streamlink1")]};
        byte[] legacyBytes=System.Security.Cryptography.ProtectedData.Protect(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(legacy),"StreamLink-profile-v2"u8.ToArray(),System.Security.Cryptography.DataProtectionScope.LocalMachine);
        File.WriteAllBytes(Path.Combine(legacyStore.DirectoryPath,"profile.dpapi"),legacyBytes);
        _=legacyStore.LoadForMaintenance();Check(!File.Exists(Path.Combine(legacyStore.DirectoryPath,"profile-before-ddns-removal.dpapi")),"maintenance reads do not write migration backups");
        var migrated=legacyStore.Load();
        Check(!migrated.Ddns.Enabled&&migrated.CloudflareDdnsToken.Length==0&&migrated.ExistingEntries.Single().Source=="https://entry.example.com/current#streamlink1","retired DNS settings migrate without erasing ordinary subscriptions");
        Check(File.ReadAllBytes(Path.Combine(legacyStore.DirectoryPath,"profile-before-ddns-removal.dpapi")).SequenceEqual(legacyBytes),"retired credentials remain only in the exact protected backup");
        var dormant=new DeviceProfile{ConnectionSource="custom",SavedNetworkSettings=new(){ConnectionSource="custom",ExistingEntries=[new(0,"203.0.113.42:45420")]}};
        Check(ControlWorker.RuntimeEntries(dormant).Length==0&&dormant.SavedNetworkSettings.ExistingEntries.Length==1,"switching to autonomous mode preserves dormant inputs without activating them as runtime entries");
        await AutonomousInvitation();
        Console.WriteLine($"PASS {checks} configuration library checks");
    }
    static async Task AutonomousInvitation()
    {
        var store=new ProfileStore(Path.Combine(ProfileStore.Root,"autonomous-invite"));string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        store.Save(new DeviceProfile{ConnectionSource="custom",DirectMode=true,ListenPort=45460,SourcePort=45461});int probes=0;
        var runtime=new MeshRuntimeServices(m=>new DirectMeshDiscovery(m),_=>Task.FromResult<IPacketAdapter>(new MemoryAdapter()),
            (_,_,_)=>{Interlocked.Increment(ref probes);return Task.FromResult<IMapping>(new PreparedMapping());},r=>new StubTransport(null),
            (_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},Path.Combine(store.DirectoryPath,"sessions")){
            Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(null),NetworkWake=()=>new MeshNetworkWake(false)
        };
        using var worker=new ControlWorker(store,runtime);worker.EnablePairNetworks();worker.StartLocal();
        async Task<UiControlReply> Ui(UiControlRequest request){request=request with{OperationId=Guid.NewGuid()};var reply=await worker.HandleUi(request,sid,default);while(reply.Operation is {Completed:false}){await Task.Delay(20);reply=await worker.HandleUi(new("status",OperationId:request.OperationId){NetworkId=reply.Status?.SelectedNetworkId??request.NetworkId},sid,default);}return reply;}
        try{
            var config=(await Ui(new("status"))).Status!.Configurations.Single();
            var created=await Ui(new("network",Network:new("create-direct"){Name="自主邀请",ConfigurationId=config.Id}));Check(created.Ok,created.Error);
            string id=created.Status!.SelectedNetworkId,network=created.Status.NetworkId;UiControlReply? invite=null;
            for(int attempt=0;attempt<20;attempt++){
                invite=await Ui(new("network",Network:new("invite",ExpectedNetwork:network)){NetworkId=id});if(invite.Ok)break;
                if(!invite.Error.Contains("尚未取得")&&!invite.Error.Contains("仍在启动"))throw new Exception(invite.Error);await Task.Delay(100);
            }
            Check(invite?.Ok==true,invite?.Error??"autonomous invitation unavailable");
            var imported=DirectPairInvitation.Import(invite!.Status!.Pairing!.Code);
            Check(probes>0&&imported.Network==network&&imported.Entries.Single().Source=="203.0.113.54:45460","serverless autonomous preparation shares its acquired candidate through an authenticated invitation without DNS publishing");
        }finally{await worker.StopLocal();}
    }
    sealed class PreparedMapping:IMapping
    {
        public IPAddress LocalAddress=>IPAddress.Any;
        public IPEndPoint PublicEndpoint=>new(IPAddress.Parse("203.0.113.54"),45460);
        public event Action<IPEndPoint>? Changed {add{}remove{}}
        public Task Maintain(CancellationToken token)=>Task.Delay(Timeout.Infinite,token);
        public ValueTask DisposeAsync()=>ValueTask.CompletedTask;
    }
    sealed class SelectorDocuments:HttpMessageHandler
    {
        public Uri? Last;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken){Last=request.RequestUri;return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK){Content=new StringContent("streamlink1=203.0.113.42:45420 streamlink2=203.0.113.43:45430")});}
    }
}
