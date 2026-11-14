using System.Net;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task PairWorkspace()
    {
        await PairLostDeliveryProtection();
        await SharedReceiverRouteProtection();
        var identity=MeshIdentity.Create("","","faketcp",direct:true,pairwise:true);
        string nodePrivate=NodeIdentityProof.GeneratePrivate();using var ephemeral=new PairKeyExchange(nodePrivate);using var another=new PairKeyExchange();
        Check(NodeIdentityProof.Valid(ephemeral.Identity,ephemeral.Commitment)&&!NodeIdentityProof.Valid(ephemeral.Identity,another.Commitment),"persistent identity proofs are bound to the exact ephemeral pairing key");
        var maximumState=new PairRoomState(Guid.NewGuid().ToString("N"),ephemeral.Commitment,new string('机',64),ephemeral.PublicKey,another.PublicKey,"",false,DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()){
            GuestIdentity=ephemeral.Identity,RequestedIp="192.168.255.254",Addressing=1,Governance=1,Rejoin=new(Guid.NewGuid().ToString("N"),254,Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),new string('A',88))
        };
        Check(DirectPairWire.Encode(new DirectPairReply(Guid.NewGuid().ToString("N"),State:DirectPairWire.ForGuest(maximumState))).Length<=DirectPairWire.MaximumDatagram,"long device names with rejoin and identity proofs stay inside the pairing datagram bound");
        Check(DirectPairWire.Encode(new DirectPairRequest(Guid.NewGuid().ToString("N"),"join",Code:DirectPairWire.EntryLocator,Commitment:ephemeral.Commitment,Name:new string('机',64)){
            EntryAdmission=true,Identity=ephemeral.Identity,Rejoin=maximumState.Rejoin,RequestedIp=maximumState.RequestedIp,TargetNetwork=identity.Pair.Network
        }).Length<=DirectPairWire.MaximumDatagram,"targeted rejoin requests with persistent identity also fit the actual wire limit");
        var enrolled=MeshIdentity.Issue(identity);var guest=MeshIdentity.Import(MeshIdentity.Export(enrolled));
        Check(guest.Directory?.Pairwise==true&&guest.Directory.Members.Length==2,"pair enrollment carries signed two-device directory");
        try{MeshIdentity.Issue(identity);throw new Exception("third member accepted");}catch(IOException){Check(true,"a third device cannot expand a two-device network");}
        try{MeshIdentity.ValidateDirectory(identity.Directory! with{Pairwise=false},identity.Pair.Network,identity.OwnerKey);throw new Exception("policy tampering accepted");}catch(CryptographicException){Check(true,"pair policy is authenticated by the network signature");}

        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var store=new ProfileStore();store.Save(new DeviceProfile{DirectMode=true,ConnectionSource="existing",ListenPort=45120,SourcePort=45121});
        string sid=WindowsIdentity.GetCurrent().User!.Value;store.AuthorizeUiUser(sid);
        var adapters=new List<MemoryAdapter>();int probes=0;
        var services=new MeshRuntimeServices(m=>new DirectMeshDiscovery(m),_=>{var a=new MemoryAdapter();lock(adapters)adapters.Add(a);return Task.FromResult<IPacketAdapter>(a);},
            (_,_,_)=>{Interlocked.Increment(ref probes);throw new IOException("forbidden autonomous probe");},r=>new StubTransport(null),
            (_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},Path.Combine(ProfileStore.Root,"sessions")){
            Candidates=(_,_,_,_)=>throw new IOException("forbidden candidates"),NetworkWake=()=>new MeshNetworkWake(false)
        };
        using var worker=new ControlWorker(services);worker.EnablePairNetworks();worker.StartLocal();
        Task<UiControlReply> Ui(UiControlRequest request)=>worker.HandleUi(request,sid,default);
        try{
            Guid firstOperation=Guid.NewGuid();var firstRequest=new UiControlRequest("network",OperationId:firstOperation,Network:new("create-direct"){Name="First"});
            var first=await Ui(firstRequest);Check(first.Ok,first.Error);
            string firstId=first.Status!.SelectedNetworkId,firstNetwork=first.Status.NetworkId;
            Check(firstId.Length==32&&first.Status.Networks.Length==1,"create allocates a stable independent local network configuration");
            var again=await Ui(firstRequest);Check(again.Ok&&again.Status!.Networks.Length==1&&again.Status.SelectedNetworkId==firstId,"lost create acknowledgement cannot duplicate a network");
            var second=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("create-direct"){Name="Second"}));Check(second.Ok,second.Error);
            string secondId=second.Status!.SelectedNetworkId,secondNetwork=second.Status.NetworkId;
            Check(secondId!=firstId&&secondNetwork!=firstNetwork&&second.Status.Networks.Length==2,"one device maintains two distinct signed pair networks concurrently");
            await Until(()=>{lock(adapters)return adapters.Count==2;},"both independent network adapters open");
            var summary=(await Ui(new("status"))).Status!;
            Check(summary.Aggregate?.NetworkCount==2&&summary.NetworkId.Length==0&&summary.SelectedNetworkId.Length==0,"device overview aggregates all networks without selecting a runtime");
            var selectedLogs=(await Ui(new("status"){NetworkId=firstId})).Status!;
            Check(selectedLogs.LogEntries is {Length:>0}&&summary.LogEntries is {Length:>0}&&
                selectedLogs.LogEntries.All(entry=>entry.Id.StartsWith(summary.LogEntries[0].Id.Split(':')[0]+":",StringComparison.Ordinal)),
                "selecting a network preserves the device log source even when newer device events arrive");
            var networkLogs=summary.Networks.SelectMany(n=>n.Status.LogEntries??[]).ToArray();
            Check(networkLogs.Length>=2&&networkLogs.Select(entry=>entry.Id).Distinct().Count()==networkLogs.Length&&networkLogs.All(entry=>entry.Timestamp>0&&!summary.LogEntries!.Any(deviceEntry=>deviceEntry.Id==entry.Id)),"network log entries have independent stable identities and absolute timestamps");
            Check(summary.Networks.Select(n=>n.Status.Settings!.ListenPort).Distinct().Count()==1&&summary.Networks.Select(n=>n.Status.Settings!.SourcePort).Distinct().Count()==2&&probes==0,"compatible receivers share one port with separate source ownership and no autonomous probing");
            var originalDefaults=summary.DeviceSettings!;
            foreach(string source in new[]{"198.51.100.42:45120","https://entry.example.test/current.txt"}){
                var fixedEntry=originalDefaults with{PathSelection="udp-only",ExistingEntries=[new(0,source)]};
                var setDefaults=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",Name:"Pinned UDP",Settings:fixedEntry)));Check(setDefaults.Ok,setDefaults.Error);
                string pinnedConfiguration=setDefaults.ConfigurationId;
                string folder=Path.Combine(ProfileStore.Root,"networks");
                var directories=Directory.GetDirectories(folder).Order().ToArray();
                string savedDefaults=JsonSerializer.Serialize(store.Load());
                int adaptersBefore;lock(adapters)adaptersBefore=adapters.Count;
                var conflict=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("create-direct",Mode:"udp"){Name="Pinned entry conflict",ConfigurationId=pinnedConfiguration}));
                Check(!conflict.Ok&&conflict.Error.Contains("接收端口")&&conflict.Error.Contains("连接配置"),"incompatible listener rejects a fixed or subscription entry instead of silently changing the published port");
                Check(conflict.Status!.Networks.Length==2&&directories.SequenceEqual(Directory.GetDirectories(folder).Order())&&JsonSerializer.Serialize(store.Load())==savedDefaults,
                    "listener conflict leaves no network reservation and preserves the saved device settings");
                lock(adapters)Check(adapters.Count==adaptersBefore,"rejected listener allocation does not open a network adapter");
                Check(conflict.Status.Networks.All(n=>n.Status.NetworkEnabled&&n.Status.Settings!.ListenPort==45120&&n.Status.Settings.PathSelection=="faketcp-only")&&probes==0,
                    "listener conflict keeps both existing networks and their protocol active without autonomous probing");
                var restoreDefaults=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("delete",pinnedConfiguration,ExpectedRevision:1)));Check(restoreDefaults.Ok,restoreDefaults.Error);
            }
            var independentSettings=originalDefaults with{PathSelection="udp-only",ListenPort=45130,ExistingEntries=[new(0,"198.51.100.42:45130")]};
            var independentDefaults=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",Name:"Independent UDP",Settings:independentSettings)));Check(independentDefaults.Ok,independentDefaults.Error);
            var independent=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("create-direct",Mode:"udp"){Name="Independent UDP port",ConfigurationId=independentDefaults.ConfigurationId}));
            Check(independent.Ok,independent.Error);string independentId=independent.Status!.SelectedNetworkId;
            Check(independent.Status.Settings!.ListenPort==45130&&independent.Status.Settings.SourcePort is not (45121 or 45123)&&independent.Status.Settings.ExistingEntries.Single().Source=="198.51.100.42:45130",
                "an explicit independent receiver permits another protocol and allocates only its colliding outgoing source port");
            await Until(()=>{lock(adapters)return adapters.Count==3;},"independent protocol adapter opens");
            var closeIndependent=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("forget-network",ExpectedNetwork:independent.Status.NetworkId,ConfirmReplace:true)){NetworkId=independentId});
            Check(closeIndependent.Ok&&closeIndependent.Status!.Networks.Length==2,"independent protocol cleanup removes its local record and retains both compatible networks");
            var resetDefaults=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("delete",independentDefaults.ConfigurationId,ExpectedRevision:1)));Check(resetDefaults.Ok,resetDefaults.Error);
            var late=await Ui(new("status",OperationId:firstOperation));Check(late.Status!.SelectedNetworkId==firstId,"operation polling resolves an originally empty creation target");
            var unknown=await Ui(new("stop"){NetworkId=Guid.NewGuid().ToString("N")});Check(!unknown.Ok&&unknown.Status!.Networks.All(n=>n.Status.NetworkEnabled),"an invalid network target cannot stop another connection");
            int disposedBeforeFirstExit;lock(adapters)disposedBeforeFirstExit=adapters.Count(a=>a.Disposed);
            var left=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("forget-network",ExpectedNetwork:firstNetwork,ConfirmReplace:true)){NetworkId=firstId});
            Check(left.Ok&&left.Status!.NetworkId.Length==0&&left.Status.Networks.Single(n=>n.Id==secondId).Status.NetworkEnabled,"offline local exit affects only its selected relationship");
            lock(adapters)Check(adapters.Count(a=>a.Disposed)==disposedBeforeFirstExit+1,"exiting one network retains the other network adapter");
            Check(store.Load().Mesh==null&&store.Load().ListenPort==45120,"network creation and exit preserve device defaults");
            var renamed=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("rename-network",ExpectedNetwork:secondNetwork){Name="Second renamed"}){NetworkId=secondId});
            Check(renamed.Ok&&renamed.Status!.Networks.Single(n=>n.Id==secondId).Name=="Second renamed","network names persist independently from authenticated identities");
            var configuration=renamed.Status!.Configurations.Single();
            var saveRequest=new UiControlRequest("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",configuration.Id,configuration.Name,configuration.Revision,configuration.Settings with{EntryRefreshSeconds=123},true));
            var saved=await Ui(saveRequest);Check(saved.Ok,saved.Error);configuration=saved.Status!.Configurations.Single();
            var deviceBefore=(await Ui(new("status"))).Status!;
            var deviceSave=new UiControlRequest("save-settings",OperationId:Guid.NewGuid()){
                SettingsBatch=new(new("settings",Settings:deviceBefore.DeviceSettings!,ExpectedRevision:deviceBefore.DeviceSettingsRevision,ConfirmReplace:true){Patch=new(DeviceName:"Shared device")},[])
            };
            var shared=await Ui(deviceSave);Check(shared.Ok,shared.Error);
            Check(shared.Status!.Networks.Single().Status.Settings!.EntryRefreshSeconds==123&&store.Load().EntryRefreshSeconds==60&&store.Load().DeviceName=="Shared device","connection configuration and global device settings persist independently");
            Check(shared.Status.Networks.All(n=>n.Status.DeviceName=="Shared device"),"global device settings refresh every context without rewriting connection configurations");
            var duplicateSave=await Ui(saveRequest);Check(duplicateSave.Ok&&duplicateSave.Status!.Configurations.Single().Revision==configuration.Revision,"configuration transaction replay returns its completed result without another revision");
            var rejected=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",configuration.Id,configuration.Name,1,configuration.Settings with{EntryRefreshSeconds=456},true)));
            Check(!rejected.Ok&&store.Load().DeviceName=="Shared device"&&rejected.Status!.Networks.Single().Status.Settings!.EntryRefreshSeconds==123,"stale configuration revision rejects the entire transaction");
            var removed=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("remove-network",ExpectedNetwork:firstNetwork,ConfirmReplace:true)){NetworkId=firstId});
            Check(!removed.Ok,"a stale removal confirmation cannot delete a changed network profile");
            var removedNow=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("remove-network",ExpectedNetwork:"",ConfirmReplace:true)){NetworkId=firstId});
            Check(!removedNow.Ok&&removedNow.Status!.Networks.Length==1,"an already removed local record cannot redirect removal to another network");
            int previousCount=removedNow.Status!.Networks.Length;
            var failed=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("join-entry"){Entry="not an endpoint",Name="Bad join"}));
            Check(!failed.Ok&&failed.Status!.Networks.Length==previousCount,"a failed initial join does not retain an empty configuration or consume a network slot");
            var copy=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("copy",configuration.Id,"Third settings",configuration.Revision)));Check(copy.Ok,copy.Error);
            string copyId=copy.ConfigurationId;
            var third=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("create-direct"){Name="Third",ConfigurationId=copyId}));Check(third.Ok,third.Error);
            string thirdId=third.Status!.SelectedNetworkId;
            var changed=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",configuration.Id,configuration.Name,configuration.Revision,configuration.Settings with{EntryRefreshSeconds=222},true)));Check(changed.Ok,changed.Error);
            configuration=changed.Status!.Configurations.Single(c=>c.Id==configuration.Id);
            var independentConfiguration=changed.Status.Configurations.Single(c=>c.Id==copyId);
            changed=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",copyId,independentConfiguration.Name,independentConfiguration.Revision,independentConfiguration.Settings with{EntryRefreshSeconds=333},true)));Check(changed.Ok,changed.Error);
            Check(changed.Status!.Networks.Single(n=>n.Id==secondId).Status.Settings!.EntryRefreshSeconds==222&&changed.Status.Networks.Single(n=>n.Id==thirdId).Status.Settings!.EntryRefreshSeconds==333,"independent saved configurations update only their selected networks");
            deviceBefore=(await Ui(new("status"))).Status!;
            var secondBefore=(await Ui(new("status"){NetworkId=secondId})).Status!;
            var thirdBefore=(await Ui(new("status"){NetworkId=thirdId})).Status!;
            UiNetworkAction Local(UiStatusDto status,int refresh)=>new("settings",Settings:status.Settings! with{EntryRefreshSeconds=refresh},ExpectedRevision:status.SettingsRevision);
            var batchRequest=new UiControlRequest("save-settings",OperationId:Guid.NewGuid()){
                NetworkId=secondId,SettingsBatch=new(new("settings",Settings:deviceBefore.DeviceSettings!,ExpectedRevision:deviceBefore.DeviceSettingsRevision){Patch=new(DeviceName:"Must not commit")},
                    [new(Local(secondBefore,444),secondId),new(Local(thirdBefore,555),thirdId)])
            };
            var batchSaved=await Ui(batchRequest);
            Check(!batchSaved.Ok&&batchSaved.Error.Contains("连接配置")&&store.Load().DeviceName=="Shared device"&&batchSaved.Status!.Networks.Single(n=>n.Id==secondId).Status.Settings!.EntryRefreshSeconds==222&&batchSaved.Status.Networks.Single(n=>n.Id==thirdId).Status.Settings!.EntryRefreshSeconds==333,"a legacy batch cannot bypass configuration references or partially update device settings");
            var batchReplay=await Ui(deviceSave);Check(batchReplay.Ok&&store.Load().DeviceName=="Shared device","global settings response loss does not repeat writes");
            var assigned=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("assign",configuration.Id,ExpectedRevision:configuration.Revision,ConfirmReconnect:true)){NetworkId=thirdId});Check(assigned.Ok,assigned.Error);
            var isolatedRejected=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",configuration.Id,configuration.Name,configuration.Revision,configuration.Settings with{EntryRefreshSeconds=777},true,Independent:true)){NetworkId=secondId});
            Check(!isolatedRejected.Ok&&isolatedRejected.Status!.Configurations.Single(c=>c.Id==configuration.Id).Revision==configuration.Revision&&isolatedRejected.Status.Networks.All(n=>n.Status.Settings!.EntryRefreshSeconds==222),"an independent edit atomically rejects a shared configuration without changing its revision or either network");
            var draftRejected=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",configuration.Id,configuration.Name,configuration.Revision,configuration.Settings with{EntryRefreshSeconds=777},true,Independent:true)));
            Check(!draftRejected.Ok&&draftRejected.Status!.Networks.All(n=>n.Status.Settings!.EntryRefreshSeconds==222),"a new-network editor cannot overwrite a configuration already attached to an existing network");
            var bindRejected=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("assign",configuration.Id,ExpectedRevision:configuration.Revision,ConfirmReconnect:true,Independent:true)){NetworkId=thirdId});
            Check(!bindRejected.Ok&&bindRejected.Status!.Networks.All(n=>n.ConfigurationId==configuration.Id),"independent assignment cannot silently create another shared reference");
            var removedRejected=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",Name:"Removed editor",Settings:configuration.Settings,Independent:true)){NetworkId=new string('f',32)});
            Check(!removedRejected.Ok&&removedRejected.Status!.Configurations.Length==assigned.Status!.Configurations.Length,"an editor whose target was removed cannot write an orphan configuration");
            var isolatedCopy=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",Name:"Isolated editor",Settings:configuration.Settings with{EntryRefreshSeconds=555},Independent:true)){NetworkId=thirdId});Check(isolatedCopy.Ok,isolatedCopy.Error);
            var isolatedAssign=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("assign",isolatedCopy.ConfigurationId,ExpectedRevision:1,ConfirmReconnect:true,Independent:true)){NetworkId=thirdId});Check(isolatedAssign.Ok,isolatedAssign.Error);
            Check(isolatedAssign.Status!.Networks.Single(n=>n.Id==thirdId).Status.Settings!.EntryRefreshSeconds==555&&isolatedAssign.Status.Networks.Single(n=>n.Id==secondId).Status.Settings!.EntryRefreshSeconds==222&&isolatedAssign.Status.Configurations.Single(c=>c.Id==configuration.Id).Revision==configuration.Revision,"copying then assigning changes only the edited legacy network and preserves its former shared configuration");
            var isolatedSaved=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",isolatedCopy.ConfigurationId,"Isolated editor",1,configuration.Settings with{EntryRefreshSeconds=556},true,Independent:true)){NetworkId=thirdId});Check(isolatedSaved.Ok,isolatedSaved.Error);
            Check(isolatedSaved.Status!.Networks.Single(n=>n.Id==thirdId).Status.Settings!.EntryRefreshSeconds==556&&isolatedSaved.Status.Networks.Single(n=>n.Id==secondId).Status.Settings!.EntryRefreshSeconds==222,"an existing independent network remains editable without affecting another network");
            assigned=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("assign",configuration.Id,ExpectedRevision:configuration.Revision,ConfirmReconnect:true)){NetworkId=thirdId});Check(assigned.Ok,assigned.Error);
            var portsBefore=assigned.Status!.Networks.ToDictionary(n=>n.Id,n=>n.Status.Settings!.SourcePort);
            var rollback=await Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",configuration.Id,configuration.Name,configuration.Revision,configuration.Settings with{SourcePort=65535,EntryRefreshSeconds=444},true)));
            Check(!rollback.Ok&&rollback.Status!.Configurations.Single(c=>c.Id==configuration.Id).Revision==configuration.Revision&&rollback.Status.Networks.All(n=>n.Status.Settings!.EntryRefreshSeconds==222&&n.Status.Settings.SourcePort==portsBefore[n.Id]),"a later consumer allocation failure preserves the shared revision and every earlier network setting");
            Check(!rollback.Status!.Configurations.Any(c=>c.Id==isolatedCopy.ConfigurationId),"detaching the last network retires independent settings while explicit shared templates remain");
        }finally{await worker.StopLocal();}
        Console.WriteLine($"PASS {checks} pair workspace checks");
    }
}
