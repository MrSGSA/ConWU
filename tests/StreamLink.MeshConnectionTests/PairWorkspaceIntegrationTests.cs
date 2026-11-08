using System.Collections.Concurrent;
using System.Net;
using System.Security.Principal;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    sealed class WorkspaceNode:IDisposable
    {
        public readonly ControlWorker Worker;
        public readonly ProfileStore Store;
        public readonly ConcurrentDictionary<string,MemoryAdapter> Adapters=new();
        public IPEndPoint? NativeTarget;
        public string? EntryOverride;
        public int Servers,Probes;
        readonly string sid;
        public WorkspaceNode(string folder,string name,WorkspaceNode? target=null,string coordination="",string pin="",CoordinatorSettings? coordinator=null,
            Func<MeshTransportRequest,IMeshTransport>? transportOverride=null,int listenPort=45200,bool reuseProfile=false,Func<PkarrClient>? pkarrFactory=null)
        {
            sid=WindowsIdentity.GetCurrent().User!.Value;
            Store=new ProfileStore(folder);if(!reuseProfile)Store.Save(new(){DeviceName=name,ConnectionSource="existing",DirectMode=coordination.Length==0,ListenPort=listenPort,SourcePort=listenPort+1,CoordinationService=coordination,CoordinationPin=pin,Coordinator=coordinator??new(),
                ExistingEntries=target==null?[new(0,"203.0.113.1:"+listenPort)]:coordination.Length>0?[new(ExistingEntry.Network,"203.0.113.1:"+listenPort)]:[]
            });Store.AuthorizeUiUser(sid);
            var services=new MeshRuntimeServices(m=>m.Pair.Direct?new DirectMeshDiscovery(m):new MeshDiscoveryClient(m),mesh=>{
                var adapter=new MemoryAdapter();Adapters[mesh.Pair.Network]=adapter;return Task.FromResult<IPacketAdapter>(adapter);
            },(_,_,_)=>{Interlocked.Increment(ref Probes);throw new IOException("autonomous probe forbidden");},request=>{
                if(request.Server){NativeTarget=request.Target;Interlocked.Increment(ref Servers);return transportOverride?.Invoke(request)??new StubTransport(null);}
                return transportOverride?.Invoke(request)??new ForwardingTransport(target?.NativeTarget??request.Target,toleratePeerOffline:true);
            },(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},Path.Combine(folder,"sessions")){
                Candidates=(_,_,_,_)=>throw new IOException("autonomous candidates forbidden"),NetworkWake=()=>new MeshNetworkWake(false),PkarrClientFactory=pkarrFactory,
                ResolveEntries=async (entries,_,ct)=>{
                    if(target!=null)while(target.NativeTarget==null)await Task.Delay(20,ct);
                    return entries.Select((e,i)=>new EntryResolution(e.PeerSlot,i,"地址",[target?.EntryOverride??target?.NativeTarget?.ToString()??"203.0.113.1:"+listenPort],"")).ToArray();
                }
            };
            Worker=new ControlWorker(Store,services);Worker.EnablePairNetworks();Worker.StartLocal();
        }
        public Task<UiControlReply> Ui(UiControlRequest request)=>Worker.HandleUi(request,sid,default);
        public async Task<UiStatusDto> State()=> (await Ui(new("status"))).Status!;
        public async Task<UiControlReply> Action(string id,UiNetworkAction action)=>await Ui(new("network",OperationId:Guid.NewGuid(),Network:action){NetworkId=id});
        public void Dispose()=>Worker.Dispose();
    }
    static async Task PairWorkspaceIntegration(string? nativeBinary=null,string? nativeFolder=null)
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        string folder=Path.Combine(ProfileStore.Root,"nodes");
        await using var wire=nativeBinary==null?null:new PairWorkspaceNativeWire(nativeBinary,nativeFolder!);
        int[] ports=wire?.Ports??[45200,45200,45200];
        using var host=new WorkspaceNode(Path.Combine(folder,"host"),"Host",transportOverride:wire==null?null:wire.Transport,listenPort:ports[0]);
        using var first=new WorkspaceNode(Path.Combine(folder,"first"),"First guest",host,transportOverride:wire==null?null:wire.Transport,listenPort:ports[1]);
        using var second=new WorkspaceNode(Path.Combine(folder,"second"),"Second guest",host,transportOverride:wire==null?null:wire.Transport,listenPort:ports[2]);
        if(wire!=null)host.EntryOverride="203.0.113.1:"+ports[0];
        string entry=host.EntryOverride??"203.0.113.1:45200";
        try{
            var one=await host.Action("",new("create-direct"){Name="Host to first"});Check(one.Ok,one.Error);
            var two=await host.Action("",new("create-direct"){Name="Host to second"});Check(two.Ok,two.Error);
            await Until(()=>host.NativeTarget!=null,"shared physical receive endpoint is prepared");
            Check(host.Servers==1,"two networks use one compatible native receiver");
            await Task.Delay(500);
            var ambiguous=await first.Action("",new("join-entry"){Entry=entry,Name="Ambiguous entry"});
            Check(!ambiguous.Ok&&ambiguous.Error.Contains("多条待配对"),"a bare shared address cannot guess between two waiting networks: "+ambiguous.Error);
            var removeSpare=await host.Action(two.Status!.SelectedNetworkId,new("remove-network",ExpectedNetwork:two.Status.NetworkId,ConfirmReplace:true));Check(removeSpare.Ok,removeSpare.Error);
            async Task<string> Join(WorkspaceNode guest,string name)
            {
                var pending=await guest.Action("",new("join-entry"){Entry=entry,Name=name});Check(pending.Ok,pending.Error);
                string id=pending.Status!.SelectedNetworkId;
                UiNetworkDto? incoming=null;UiPairingDto? pairing=null;
                for(int attempt=0;attempt<80;attempt++){
                    await guest.Action(id,new("pair-poll"));
                    incoming=(await host.State()).Networks.FirstOrDefault(n=>n.Status.Pairing is {Owner:true,Candidate.Length:>0} p&&p.PeerName==guest.Store.Load().DeviceName);
                    pairing=incoming?.Status.Pairing;if(pairing?.Verification.Length>0)break;
                    await Task.Delay(50);
                }
                Check(incoming!=null&&pairing?.Verification.Length==6,"shared entry dispatches an approval to the matching pair context: "+name);
                var approved=await host.Action(incoming!.Id,new("approve",ExpectedNetwork:incoming.Status.NetworkId,Verification:pairing!.Verification,Candidate:pairing.Candidate,ProposedIp:pairing.ProposedIp));
                Check(approved.Ok,approved.Error);
                for(int attempt=0;attempt<60;attempt++){
                    var polled=await guest.Action(id,new("pair-poll"));Check(polled.Ok,polled.Error);
                    if(polled.Status!.NetworkId.Length>0)return id;await Task.Delay(50);
                }
                throw new Exception("approved guest never received its pair credential");
            }
            string firstId=await Join(first,"First relation");
            var preparedSecond=await host.Action("",new("create-direct"){Name="Host to second"});Check(preparedSecond.Ok,preparedSecond.Error);
            string secondId=await Join(second,"Second relation");
            UiStatusDto current=await host.State();
            for(int attempt=0;attempt<150&&current.Aggregate!.ConnectedNetworks!=2;attempt++){await Task.Delay(100);current=await host.State();}
            if(current.Aggregate!.ConnectedNetworks!=2){foreach(var node in new[]{host,first,second})foreach(var network in (await node.State()).Networks){Console.WriteLine(network.Name+" "+network.Status.State+" "+network.Status.Connection?.Detail);foreach(var line in network.Status.Logs)Console.WriteLine(line);}}
            Check(current.Aggregate.ConnectedNetworks==2,"two independently approved encrypted networks connect through a single physical entry");
            var a=(await first.State()).Networks.Single(n=>n.Id==firstId);var b=(await second.State()).Networks.Single(n=>n.Id==secondId);
            var hostA=current.Networks.Single(n=>n.Status.NetworkId==a.Status.NetworkId);var hostB=current.Networks.Single(n=>n.Status.NetworkId==b.Status.NetworkId);
            Check(a.Status.NetworkId!=b.Status.NetworkId&&a.Status.Peers.Single().VirtualIp!=b.Status.Peers.Single().VirtualIp,"pair relations keep separate identities and virtual addresses");
            Check(a.Status.Peers.Single().DeviceId==host.Store.Load().Device&&b.Status.Peers.Single().DeviceId==host.Store.Load().Device,"the same authenticated host keeps a stable device identity across different networks");
            host.Adapters[a.Status.NetworkId].Outgoing.Add(Packet(hostA.Status.VirtualIp,a.Status.VirtualIp));
            host.Adapters[b.Status.NetworkId].Outgoing.Add(Packet(hostB.Status.VirtualIp,b.Status.VirtualIp));
            first.Adapters[a.Status.NetworkId].Outgoing.Add(Packet(a.Status.VirtualIp,hostA.Status.VirtualIp));
            second.Adapters[b.Status.NetworkId].Outgoing.Add(Packet(b.Status.VirtualIp,hostB.Status.VirtualIp));
            bool delivered=false;
            for(int attempt=0;attempt<100;attempt++){
                var hs=await host.State();var f=await first.State();var s=await second.State();
                delivered=hs.Aggregate!.Peers.All(p=>p.Peer.ReceivedBytes>=1280)&&f.Aggregate!.ReceivedBytes>=1280&&s.Aggregate!.ReceivedBytes>=1280;
                if(delivered)break;await Task.Delay(50);
            }
            Check(delivered,"full-MTU inner packets cross both pair networks in both directions");
            if(wire!=null){
                const int count=1200;
                long beforeA=(await first.State()).Aggregate!.ReceivedBytes,beforeB=(await second.State()).Aggregate!.ReceivedBytes;
                for(int index=0;index<count;index++){
                    host.Adapters[a.Status.NetworkId].Outgoing.Add(Packet(hostA.Status.VirtualIp,a.Status.VirtualIp));
                    host.Adapters[b.Status.NetworkId].Outgoing.Add(Packet(hostB.Status.VirtualIp,b.Status.VirtualIp));
                    if(index%8==0)await Task.Delay(1);
                }
                bool burst=false;
                for(int attempt=0;attempt<100;attempt++){
                    burst=(await first.State()).Aggregate!.ReceivedBytes-beforeA>=count*1280*.95&&(await second.State()).Aggregate!.ReceivedBytes-beforeB>=count*1280*.95;
                    if(burst)break;await Task.Delay(50);
                }
                Check(burst,"multi-network business bursts exceed the control budget without being misclassified or starving either pair");
                await Task.Delay(1100);
                Check(LegacyTransportLedger.Shared.Snapshot().Resources.Where(r=>r.State=="Running").Sum(r=>r.Wire?.BusinessPackets??0)>=count,
                    "native injection evidence classifies CNW1-wrapped MeshLink data as business");
            }
            long secondReceived=(await second.State()).Aggregate!.ReceivedBytes;
            host.Adapters[a.Status.NetworkId].Outgoing.Add(Packet(hostA.Status.VirtualIp,b.Status.VirtualIp));await Task.Delay(150);
            Check((await second.State()).Aggregate!.ReceivedBytes==secondReceived,"a network cannot forward a packet to a different pair's address");
            using(var noise=new System.Net.Sockets.UdpClient()){
                await noise.SendAsync(new byte[4096],host.NativeTarget!);
                await noise.SendAsync(DirectPairWire.Encode(new DirectPairRequest(Guid.NewGuid().ToString("N"),"join"){TargetNetwork=null!}),host.NativeTarget!);
                await noise.SendAsync(DirectPairWire.Encode(new DirectPairRequest(Guid.NewGuid().ToString("N"),"join"){TargetNetwork="not-a-network"}),host.NativeTarget!);
                for(int index=0;index<20;index++)await noise.SendAsync(PairNetworkFrame.Wrap(b.Status.NetworkId,new byte[MeshLink.Overhead]),host.NativeTarget!);
            }
            second.Adapters[b.Status.NetworkId].Outgoing.Add(Packet(b.Status.VirtualIp,hostB.Status.VirtualIp));
            bool survived=false;for(int attempt=0;attempt<60;attempt++){var hs=await host.State();survived=hs.Aggregate!.Peers.Single(p=>p.NetworkId==hostB.Id).Peer.ReceivedBytes>=2560;if(survived)break;await Task.Delay(50);}
            Check(survived,"oversized, null-target, malformed-target and unauthenticated input cannot terminate the shared receiver or another live network");
            var spare=await host.Action("",new("create-direct"){Name="Duplicate attempt"});Check(spare.Ok,spare.Error);
            var invite=await host.Action(spare.Status!.SelectedNetworkId,new("invite",ExpectedNetwork:spare.Status.NetworkId));Check(invite.Ok,invite.Error);
            var duplicate=await first.Action("",new("join-invitation",Code:invite.Status!.Pairing!.Code){Name="Duplicate guest"});Check(duplicate.Ok,duplicate.Error);
            string duplicateId=duplicate.Status!.SelectedNetworkId;UiPairingDto? duplicatePair=null;
            for(int attempt=0;attempt<100;attempt++){
                await first.Action(duplicateId,new("pair-poll"));
                duplicatePair=(await host.State()).Networks.Single(n=>n.Id==spare.Status!.SelectedNetworkId).Status.Pairing;
                if(duplicatePair?.Verification.Length==6)break;await Task.Delay(50);
            }
            Check(duplicatePair?.Verification.Length==6,"duplicate device application reaches an independent approval context");
            var duplicateApproval=await host.Action(spare.Status!.SelectedNetworkId,new("approve",ExpectedNetwork:spare.Status.NetworkId,Verification:duplicatePair!.Verification,Candidate:duplicatePair.Candidate,ProposedIp:duplicatePair.ProposedIp));
            Check(!duplicateApproval.Ok&&duplicateApproval.Error.Contains("已保存与此设备"),"stable device proof prevents a second relationship from duplicating an already enrolled device");
            var canceled=await first.Action(duplicateId,new("pair-cancel"));Check(canceled.Ok&&canceled.Status!.Networks.Length==1,"canceling an unapproved attempt removes only the temporary configuration");
            var discard=await host.Action(spare.Status.SelectedNetworkId,new("remove-network",ExpectedNetwork:spare.Status.NetworkId,ConfirmReplace:true));Check(discard.Ok,discard.Error);
            var left=await host.Action(hostA.Id,new("forget-network",ExpectedNetwork:a.Status.NetworkId,ConfirmReplace:true));Check(left.Ok,left.Error);
            await Task.Delay(150);
            Check((await host.State()).Networks.Single(n=>n.Id==hostB.Id).Status.DirectPeers==1&&host.Servers==1,"exiting one network preserves the shared receiver and other healthy direct link");
            Check(host.Probes+first.Probes+second.Probes==0,"all supplied-entry contexts stay free of autonomous traversal");
        }finally{await Task.WhenAll(host.Worker.StopLocal(),first.Worker.StopLocal(),second.Worker.StopLocal());}
        if(wire!=null)Check(wire.SawHttp&&wire.FromClients>0&&wire.FromServers>0,"all pair networks use the actual native FakeTCP and HTTP carriage");
        Console.WriteLine($"PASS {checks} real multi-context pair integration checks; {(wire==null?"managed loopback transports":"production C++ FakeTCP with a loopback raw carrier")}, not physical WAN");
    }
}
