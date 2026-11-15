using System.Diagnostics;
using System.Net;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task EntryPreparationChecks()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var expected=new PreparedMapping();
        var overridden=MeshRuntimeServices.Default with{Probe=(_,_,_)=>Task.FromResult<IMapping>(expected)};
        var overriddenResult=await overridden.PrepareEntry(new(),_=>{},_=>throw new Exception("injected probe bypassed"),CancellationToken.None);
        Check(ReferenceEquals(expected,overriddenResult),"an overridden provider never falls through to the production gateway");
        await overriddenResult.DisposeAsync();
        bool fail=true;int calls=0;
        Task<IMapping> Prepare(Action<EntryProbeProgress> progress,CancellationToken token){
            Interlocked.Increment(ref calls);progress(new("GatewayMapping","TCP STUN 已返回候选，但网关拒绝映射"));
            if(fail)throw new EntryProbeException("GatewayMapping","Unavailable","本层网关不支持自动映射",new IOException("fixture rejection"));
            return Task.FromResult<IMapping>(new PreparedMapping());
        }
        using var host=new WorkspaceNode(Path.Combine(ProfileStore.Root,"entry-preparation"),"Entry host",mappingFactory:()=>new PreparedMapping(),entryProbe:Prepare);
        var config=(await host.State()).Configurations.Single();
        var settings=config.Settings with{ConnectionSource="custom",ExistingEntries=[],DirectMode=true,DiscoveryMode="direct",PkarrPublish=false};
        var saved=await host.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",config.Id,config.Name,config.Revision,settings)));
        Check(saved.Ok,saved.Error);
        var created=await host.Action("",new("create-direct",Mode:"faketcp"){Name="Entry diagnostics",LocalEnrollment=true,ConfigurationId=config.Id});
        Check(created.Ok,created.Error);var network=created.Status!.Networks.Single();string id=network.Id,networkId=network.Status.NetworkId;
        await Until(asyncCondition,"failed synchronous entry provider is captured while the network remains available");
        // Entry failure and receiver readiness are independent asynchronous
        // prerequisites. The fake probe may fail before the adapter opens.
        bool asyncCondition()=>host.State().GetAwaiter().GetResult().Networks.Single().Status.EntryPreparation is {State:"Unavailable",ReceiverReady:true};
        var failed=(await host.State()).Networks.Single().Status.EntryPreparation!;
        Check(failed.Stage=="GatewayMapping"&&failed.FailureCode=="Unavailable"&&failed.Attempt>=1&&failed.RetryAt>0&&failed.ReceiverReady,
            "live status identifies the failed mapping stage, retry schedule and healthy receiver");
        int before=calls;var clock=Stopwatch.StartNew();
        var invitation=await host.Action(id,new("invite-compact",ExpectedNetwork:networkId));
        Check(!invitation.Ok&&invitation.Error.Contains("网关不支持")&&clock.Elapsed<TimeSpan.FromSeconds(5)&&calls>before,
            "generate retries a failed round and returns its actual cause without the full thirty-second wait");
        var retained=(await host.State()).Networks.Single();
        Check(retained.Id==id&&retained.Status.NetworkId==networkId&&retained.Status.ServiceReady&&retained.Status.Pairing?.Code is not {Length:>0},
            "a failed entry creates no placeholder code and retains the network and background service");
        fail=false;
        var recovered=await host.Action(id,new("invite-compact",ExpectedNetwork:networkId));
        Check(recovered.Ok,"a recovered gateway can generate a direct code without recreating the network: "+recovered.Error);
        var ready=(await host.State()).Networks.Single().Status;
        Check(ready.EntryPreparation?.State=="Candidate"&&ready.EntryPreparation.FailureCode.Length==0&&ready.Pairing?.Format=="compact"&&CompactDirectCode.Import(ready.Pairing.Code).Mode=="faketcp",
            "successful retry clears the old failure and emits a normal sixteen-symbol invitation");
        await host.Worker.StopLocal();
        using var broken=new WorkspaceNode(Path.Combine(ProfileStore.Root,"entry-receiver-failure"),"Broken receiver",mappingFactory:()=>new PreparedMapping(),
            transportOverride:r=>r.Server?throw new IOException("fixture receiver port occupied"):new StubTransport(null));
        var receiverCreated=await broken.Action("",new("create-direct",Mode:"faketcp"){LocalEnrollment=true,Name="Receiver failure"});
        Check(receiverCreated.Ok,receiverCreated.Error);var receiverNetwork=receiverCreated.Status!.Networks.Single();
        await Until(()=>broken.State().GetAwaiter().GetResult().Networks.Single().Status.EntryPreparation?.ReceiverError.Contains("port occupied")==true,
            "listener startup failure is independently observable");
        var nativeClock=Stopwatch.StartNew();
        var nativeFailed=await broken.Action(receiverNetwork.Id,new("invite-compact",ExpectedNetwork:receiverNetwork.Status.NetworkId));
        Check(!nativeFailed.Ok&&nativeFailed.Error.Contains("port occupied")&&nativeClock.Elapsed<TimeSpan.FromSeconds(3),
            "native listener failure reports its cause immediately instead of waiting for a gateway timeout");
        await broken.Worker.StopLocal();
        Console.WriteLine($"PASS {checks} entry preparation integration checks; isolated profiles and transports only");
    }
    static async Task MimicNetworkPorts()
    {
        string folder=Path.Combine(Path.GetTempPath(),"conwu-mimic-ports-"+Guid.NewGuid().ToString("N"));
        string[] identities;
        using(var host=new WorkspaceNode(folder,"Mimic ports",mappingFactory:()=>new PreparedMapping())){
        var configuration=(await host.State()).Configurations.Single();
        var settings=configuration.Settings with{PathSelection="mimic-only",ConnectionSource="custom",DirectMode=true,DiscoveryMode="direct",ExistingEntries=[]};
        var saved=await host.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",configuration.Id,configuration.Name,configuration.Revision,settings)));
        Check(saved.Ok,saved.Error);
        var first=await host.Action("",new("create-direct",Mode:"mimic"){Name="First Mimic",LocalEnrollment=true,ConfigurationId=configuration.Id});Check(first.Ok,first.Error);
        var second=await host.Action("",new("create-direct",Mode:"mimic"){Name="Second Mimic",LocalEnrollment=true,ConfigurationId=configuration.Id});Check(second.Ok,second.Error);
        var networks=(await host.State()).Networks;
        Check(networks.Length==2&&networks.Select(n=>n.Status.Settings!.ListenPort).Distinct().Count()==2,
            "two autonomous Mimic networks allocate distinct receiver ports instead of competing for one STUN/native owner");
        Check(networks.Select(n=>n.Status.NetworkId).Distinct().Count()==2&&networks.All(n=>n.Status.NetworkEnabled),
            "automatic receiver allocation preserves both network identities and enabled state");
        identities=networks.Select(n=>n.Status.NetworkId).Order().ToArray();
        await host.Worker.StopLocal();
        }
        var parent=new ProfileStore(folder);
        var stores=Directory.GetDirectories(Path.Combine(folder,"networks")).Select(path=>new ProfileStore(path,parent)).ToArray();
        int shared=stores[0].Load().ListenPort;
        var legacy=stores[1].Load();legacy.ListenPort=shared;legacy.SavedNetworkSettings=legacy.SavedNetworkSettings! with{ListenPort=shared};stores[1].Save(legacy);
        using(var restored=new WorkspaceNode(folder,"Mimic ports",reuseProfile:true,mappingFactory:()=>new PreparedMapping())){
            var rows=(await restored.State()).Networks;
            Check(rows.Select(n=>n.Status.Settings!.ListenPort).Distinct().Count()==2,
                "startup separates legacy shared autonomous Mimic ports before workers compete for them");
            Check(rows.Select(n=>n.Status.NetworkId).Order().SequenceEqual(identities),"receiver migration preserves both saved network identities");
            await restored.Worker.StopLocal();
        }
    }
}
