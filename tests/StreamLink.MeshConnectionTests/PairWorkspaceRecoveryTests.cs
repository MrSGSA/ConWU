using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task PairLostDeliveryProtection()
    {
        using var host=new DirectPairHost(entryAdmission:true);
        string deviceKey=NodeIdentityProof.GeneratePrivate();
        using var owner=new PairKeyExchange();using var guest=new PairKeyExchange(deviceKey);
        var ticket=await host.Create(owner,"Host",default);
        DirectPairRequest Request(PairKeyExchange key)=>new(Guid.NewGuid().ToString("N"),"join",Code:DirectPairWire.EntryLocator,Commitment:key.Commitment,Name:"Guest"){EntryAdmission=true,Identity=key.Identity};
        var original=Request(guest);var joined=DirectPairWire.Decode<DirectPairReply>(host.Handle(DirectPairWire.Encode(original))!).Ticket!;
        await host.Reveal(ticket,true,owner,default);
        host.Handle(DirectPairWire.Encode(new DirectPairRequest(Guid.NewGuid().ToString("N"),"reveal",Room:joined.Room,Token:joined.Token,PublicKey:guest.PublicKey){EntryAdmission=true}));
        await host.Approve(ticket,joined.Candidate,new string('A',44),default);
        using var stranger=new PairKeyExchange(NodeIdentityProof.GeneratePrivate());
        Check(!host.Matches(Request(stranger))&&!host.CanCreate,"an unrelated persistent identity cannot release another device's undelivered approval");
        using var renewed=new PairKeyExchange(deviceKey);var recovery=Request(renewed);
        Check(!host.Matches(recovery with{Identity=recovery.Identity! with{Signature="invalid"}})&&!host.CanCreate,"forged identity recovery leaves the approved delivery intact");
        var replay=DirectPairWire.Decode<DirectPairReply>(host.Handle(DirectPairWire.Encode(original))!);
        Check(!replay.Retryable&&!host.CanCreate,"replaying the old commitment does not release an approved but unreceived delivery");
        Check(host.Matches(recovery),"only the same signed device identity bound to a new commitment can request delivery recovery");
        var released=DirectPairWire.Decode<DirectPairReply>(host.Handle(DirectPairWire.Encode(recovery))!);
        Check(released.Retryable&&released.Ticket==null&&released.State==null&&host.CanCreate,"identity recovery returns only a retry instruction and grants no enrollment");
        using var nextOwner=new PairKeyExchange();var next=await host.Create(nextOwner,"Host",default);
        Check(next.Room!=ticket.Room&&next.HostCommitment!=ticket.HostCommitment,"the next approval uses a fresh room and host ECDH commitment");
        var late=DirectPairWire.Decode<DirectPairReply>(host.Handle(DirectPairWire.Encode(new DirectPairRequest(Guid.NewGuid().ToString("N"),"received",Room:joined.Room,Token:joined.Token){EntryAdmission=true}))!);
        Check(late.Error.Length>0&&(await host.Poll(next,true,default)).Approved==false,"a late receipt from the old room cannot approve or mutate the replacement room");
    }
    static async Task<(string Id,UiNetworkDto Incoming,UiPairingDto Pairing)> PendingPair(WorkspaceNode host,WorkspaceNode guest)
    {
        await Until(()=>host.NativeTarget!=null,"fixture shared receiver has been attached before resolving its loopback carrier");
        var pending=await guest.Action("",new("join-entry"){Entry="203.0.113.1:45200",Name="Recovered relation"});Check(pending.Ok,pending.Error);
        string id=pending.Status!.SelectedNetworkId;
        for(int attempt=0;attempt<100;attempt++){
            var poll=await guest.Action(id,new("pair-poll"));Check(poll.Ok,poll.Error);
            var incoming=(await host.State()).Networks.FirstOrDefault(n=>n.Status.Pairing is {Owner:true,Candidate.Length:>0} p&&p.PeerName==guest.Store.Load().DeviceName);
            if(incoming?.Status.Pairing is {Verification.Length:6} pairing)return(id,incoming,pairing);
            await Task.Delay(50);
        }
        throw new Exception("pending approval never became ready");
    }
    static async Task ApprovePending(WorkspaceNode host,(string Id,UiNetworkDto Incoming,UiPairingDto Pairing) pending)
    {
        var approved=await host.Action(pending.Incoming.Id,new("approve",ExpectedNetwork:pending.Incoming.Status.NetworkId,
            Verification:pending.Pairing.Verification,Candidate:pending.Pairing.Candidate,ProposedIp:pending.Pairing.ProposedIp));
        Check(approved.Ok,approved.Error);
    }
    static async Task ReceiveApproval(WorkspaceNode guest,string id)
    {
        for(int attempt=0;attempt<80;attempt++){
            var poll=await guest.Action(id,new("pair-poll"));Check(poll.Ok,poll.Error);
            if(poll.Status!.NetworkId.Length>0)return;
            await Task.Delay(50);
        }
        throw new Exception("approved enrollment was not imported");
    }
    static async Task PairWorkspaceRecovery()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        string root=Path.Combine(ProfileStore.Root,"recovery");
        var host=new WorkspaceNode(Path.Combine(root,"host"),"Recovery host");
        var first=new WorkspaceNode(Path.Combine(root,"first"),"Recovery first",host);
        var second=new WorkspaceNode(Path.Combine(root,"second"),"Recovery second",host);
        try{
            var created=await host.Action("",new("create-direct"){Name="First recovery network"});Check(created.Ok,created.Error);
            var pending=await PendingPair(host,first);await ApprovePending(host,pending);
            var granted=(await host.State()).Networks.Single().Status;
            int oldSlot=granted.Peers.Single().Slot;string oldAddress=granted.Peers.Single().VirtualIp;
            string device=first.Store.Load().Device;
            await first.Worker.StopLocal();first.Dispose();
            first=new WorkspaceNode(Path.Combine(root,"first"),"Recovery first",host,reuseProfile:true);
            Check(first.Store.Load().Device==device&&(await first.State()).Networks.Length==0,"a crashed, unreceived enrollment keeps device identity and retires its incomplete local reservation");
            var restarted=await PendingPair(host,first);
            Check(restarted.Pairing.Candidate!=pending.Pairing.Candidate&&restarted.Pairing.ReplacingSlot==oldSlot,"lost authorization delivery recovers into a new approval for the same persistent device");
            Check((await host.State()).Networks.Single().Status.Peers.Single().Slot==oldSlot,"identity recovery alone never replaces a member before owner approval");
            await ApprovePending(host,restarted);await ReceiveApproval(first,restarted.Id);
            var after=(await host.State()).Networks.Single().Status;
            Check(after.Peers.Length==1&&after.Peers.Single().Slot!=oldSlot&&after.Peers.Single().VirtualIp==oldAddress,"fresh approval revokes the lost membership and preserves its virtual address without a duplicate device");
            var secondCreated=await host.Action("",new("create-direct"){Name="Second recovery network"});Check(secondCreated.Ok,secondCreated.Error);
            var secondPending=await PendingPair(host,second);await ApprovePending(host,secondPending);await ReceiveApproval(second,secondPending.Id);
            Task Connected()=>PairReady(host,10000,first,second);
            await Connected();
            string[] identities=(await host.State()).Networks.Select(n=>n.Status.NetworkId).Order().ToArray();
            string settings=JsonSerializer.Serialize((await host.State()).DeviceSettings);
            await Task.WhenAll(host.Worker.StopLocal(),first.Worker.StopLocal(),second.Worker.StopLocal());
            host.Dispose();first.Dispose();second.Dispose();
            host=new WorkspaceNode(Path.Combine(root,"host"),"Recovery host",reuseProfile:true);
            first=new WorkspaceNode(Path.Combine(root,"first"),"Recovery first",host,reuseProfile:true);
            second=new WorkspaceNode(Path.Combine(root,"second"),"Recovery second",host,reuseProfile:true);
            await Connected();var restored=await host.State();
            Check(restored.Networks.Select(n=>n.Status.NetworkId).Order().SequenceEqual(identities)&&restored.Aggregate?.ConnectedNetworks==2,"all three real workers restart from independently saved pair profiles and reconnect both relationships");
            Check(JsonSerializer.Serialize(restored.DeviceSettings)==settings&&host.Servers==1,"restart retains device settings and reconstructs exactly one shared receiver");
            foreach(var guest in new[]{first,second}){
                var g=(await guest.State()).Networks.Single().Status;
                host.Adapters[g.NetworkId].Outgoing.Add(Packet(g.Peers.Single().VirtualIp,g.VirtualIp));
                guest.Adapters[g.NetworkId].Outgoing.Add(Packet(g.VirtualIp,g.Peers.Single().VirtualIp));
            }
            bool delivered=false;for(int i=0;i<100;i++){
                delivered=(await host.State()).Aggregate!.Peers.All(p=>p.Peer.ReceivedBytes>=1280)&&
                    (await first.State()).Aggregate!.ReceivedBytes>=1280&&(await second.State()).Aggregate!.ReceivedBytes>=1280;
                if(delivered)break;await Task.Delay(50);
            }
            Check(delivered,"both restored encrypted network paths carry full-MTU business packets in both directions");
        }finally{
            await Task.WhenAll(host.Worker.StopLocal(),first.Worker.StopLocal(),second.Worker.StopLocal());
            host.Dispose();first.Dispose();second.Dispose();
        }
        Console.WriteLine($"PASS {checks} pair enrollment-loss and restart checks; loopback data transports");
    }
}
