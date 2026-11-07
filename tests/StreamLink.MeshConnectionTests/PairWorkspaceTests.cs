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
            Check(summary.Networks.Select(n=>n.Status.Settings!.ListenPort).Distinct().Count()==1&&summary.Networks.Select(n=>n.Status.Settings!.SourcePort).Distinct().Count()==2&&probes==0,"compatible receivers share one port with separate source ownership and no autonomous probing");
            var late=await Ui(new("status",OperationId:firstOperation));Check(late.Status!.SelectedNetworkId==firstId,"operation polling resolves an originally empty creation target");
            var unknown=await Ui(new("stop"){NetworkId=Guid.NewGuid().ToString("N")});Check(!unknown.Ok&&unknown.Status!.Networks.All(n=>n.Status.NetworkEnabled),"an invalid network target cannot stop another connection");
            var left=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("forget-network",ExpectedNetwork:firstNetwork,ConfirmReplace:true)){NetworkId=firstId});
            Check(left.Ok&&left.Status!.NetworkId.Length==0&&left.Status.Networks.Single(n=>n.Id==secondId).Status.NetworkEnabled,"offline local exit affects only its selected relationship");
            lock(adapters)Check(adapters.Count(a=>a.Disposed)==1,"exiting one network retains the other network adapter");
            Check(store.Load().Mesh==null&&store.Load().ListenPort==45120,"network creation and exit preserve device defaults");
            var renamed=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("rename-network",ExpectedNetwork:secondNetwork){Name="Second renamed"}){NetworkId=secondId});
            Check(renamed.Ok&&renamed.Status!.Networks.Single(n=>n.Id==secondId).Name=="Second renamed","network names persist independently from authenticated identities");
            var settingsBefore=renamed.Status!;var changed=settingsBefore.Settings! with{EntryRefreshSeconds=123,Ddns=new(false,"ddns.example.test")};
            var saveRequest=new UiControlRequest("network",OperationId:Guid.NewGuid(),Network:new("settings",Settings:changed,ExpectedRevision:settingsBefore.SettingsRevision){ExpectedDeviceRevision=settingsBefore.DeviceSettingsRevision}){NetworkId=secondId};
            var saved=await Ui(saveRequest);Check(saved.Ok,saved.Error);
            Check(saved.Status!.Settings!.EntryRefreshSeconds==123&&store.Load().EntryRefreshSeconds==60&&store.Load().Ddns.Domain=="ddns.example.test","one save separates per-network options from shared DDNS settings");
            Check(saved.Status.Networks.Single(n=>n.Id==firstId).Status.Settings!.EntryRefreshSeconds==60&&saved.Status.Networks.All(n=>n.Status.Settings!.Ddns!.Domain=="ddns.example.test"),"shared settings refresh all contexts without overwriting their independent options");
            var duplicateSave=await Ui(saveRequest);Check(duplicateSave.Ok,"settings transaction replay returns its completed result");
            var previousDefault=store.Load();var current=saved.Status;
            var rejected=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("settings",Settings:current.Settings! with{EntryRefreshSeconds=456,Ddns=new(false,"different.example.test")},ExpectedRevision:current.SettingsRevision){ExpectedDeviceRevision="stale"}){NetworkId=secondId});
            Check(!rejected.Ok&&store.Load().Ddns==previousDefault.Ddns&&rejected.Status!.Settings!.EntryRefreshSeconds==123,"stale shared revision rejects the entire settings transaction");
            var removed=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("remove-network",ExpectedNetwork:firstNetwork,ConfirmReplace:true)){NetworkId=firstId});
            Check(!removed.Ok,"a stale removal confirmation cannot delete a changed network profile");
            var removedNow=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("remove-network",ExpectedNetwork:"",ConfirmReplace:true)){NetworkId=firstId});
            Check(removedNow.Ok&&removedNow.Status!.Networks.Length==1,"explicit profile removal releases only the selected empty configuration");
            int previousCount=removedNow.Status!.Networks.Length;
            var failed=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("join-entry"){Entry="not an endpoint",Name="Bad join"}));
            Check(!failed.Ok&&failed.Status!.Networks.Length==previousCount,"a failed initial join does not retain an empty configuration or consume a network slot");
            var third=await Ui(new("network",OperationId:Guid.NewGuid(),Network:new("create-direct"){Name="Third"}));Check(third.Ok,third.Error);
            string thirdId=third.Status!.SelectedNetworkId;
            var deviceBefore=(await Ui(new("status"))).Status!;
            var secondBefore=(await Ui(new("status"){NetworkId=secondId})).Status!;
            var thirdBefore=(await Ui(new("status"){NetworkId=thirdId})).Status!;
            UiNetworkAction Local(UiStatusDto status,int refresh)=>new("settings",Settings:status.Settings! with{EntryRefreshSeconds=refresh},ExpectedRevision:status.SettingsRevision);
            var batchRequest=new UiControlRequest("save-settings",OperationId:Guid.NewGuid()){
                NetworkId=secondId,SettingsBatch=new(new("settings",Settings:deviceBefore.Settings! with{Ddns=new(false,"batch.example.test")},ExpectedRevision:deviceBefore.SettingsRevision),
                    [new(Local(secondBefore,222),secondId),new(Local(thirdBefore,333),thirdId)])
            };
            var batchSaved=await Ui(batchRequest);Check(batchSaved.Ok,batchSaved.Error);
            Check(batchSaved.Status!.Networks.Single(n=>n.Id==secondId).Status.Settings!.EntryRefreshSeconds==222&&batchSaved.Status.Networks.Single(n=>n.Id==thirdId).Status.Settings!.EntryRefreshSeconds==333&&store.Load().Ddns.Domain=="batch.example.test","one global settings transaction commits every network draft and shared configuration");
            var batchReplay=await Ui(batchRequest);Check(batchReplay.Ok,"global settings response loss does not repeat writes");
            secondBefore=(await Ui(new("status"){NetworkId=secondId})).Status!;thirdBefore=(await Ui(new("status"){NetworkId=thirdId})).Status!;
            var bad=Local(thirdBefore,555) with{Settings=thirdBefore.Settings! with{SourcePort=thirdBefore.Settings.ListenPort,EntryRefreshSeconds=555}};
            var rollback=await Ui(new("save-settings",OperationId:Guid.NewGuid()){NetworkId=secondId,SettingsBatch=new(null,[new(Local(secondBefore,444),secondId),new(bad,thirdId)])});
            Check(!rollback.Ok&&rollback.Status!.Networks.Single(n=>n.Id==secondId).Status.Settings!.EntryRefreshSeconds==222&&rollback.Status.Networks.Single(n=>n.Id==thirdId).Status.Settings!.EntryRefreshSeconds==333,"a later invalid network rolls back all earlier settings in the global transaction");
        }finally{await worker.StopLocal();}
        Console.WriteLine($"PASS {checks} pair workspace checks");
    }
}
