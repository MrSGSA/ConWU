using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using StreamLink.Core;
using StreamLink.Discovery;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    static int Code(IResult result)=>(result as IStatusCodeHttpResult)?.StatusCode??200;
    static void Invalid(Action action,string reason){try{action();}catch(Exception ex)when(ex is IOException or CryptographicException or FormatException){Check(true,reason);return;}throw new Exception(reason+" was accepted");}
    static async Task Governance(bool includeService=true)
    {
        string root=Path.Combine(Path.GetTempPath(),"streamlink-governance-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        try{
            var registry=new MeshRegistry(root);
            var a=MeshIdentity.Create("https://coordinator.example/","","faketcp","10.171.139.7");
            var legacy=a.Directory!;MeshGovernance.Enable(a);a.Validate();
            Check(a.IsDecentralized&&a.CanManage&&a.LocalIp=="10.171.139.7","explicit migration preserves network identity and custom address");
            var context=new DefaultHttpContext();context.Request.Headers.Authorization="Bearer "+a.Pair.Auth;
            IResult Commit(MeshDirectory proposal,string parent)=>registry.Membership(context,a.Pair.Network,new(parent,proposal));
            Check(Code(Commit(a.Directory!,""))==200,"production registry registers an equal-membership genesis");
            var anchor=a.Directory!;
            var b=Guest(a);
            Check(b.CanManage&&!b.IsOwner&&b.OwnerPrivate.Length==0&&b.IntroducerSlot==a.Self.Slot,"approved guest has equal permissions with its own keys only");
            Check(Code(Commit(a.Directory!,MeshGovernance.Head(anchor)))==200,"approval is committed against the expected membership head");
            var approved=a.Directory!;
            var failedSave=CopyMesh(a);_=Guest(failedSave);
            string obstacle=Path.Combine(root,"mesh-networks.json.tmp");Directory.CreateDirectory(obstacle);
            try{Commit(failedSave.Directory!,MeshGovernance.Head(approved));throw new Exception("failed storage was acknowledged");}catch(IOException){Check(true,"coordinator does not acknowledge a failed durable save");}catch(UnauthorizedAccessException){Check(true,"coordinator does not acknowledge a failed durable save");}
            Directory.Delete(obstacle);
            var retained=(MeshSnapshot)((IValueHttpResult)registry.Read(context,a.Pair.Network)).Value!;
            Check(MeshGovernance.Head(retained.Directory)==MeshGovernance.Head(approved),"failed coordinator save restores the previous visible membership");
            var c=Guest(b);
            Check(c.IntroducerSlot==b.Self.Slot&&c.CanManage&&c.OwnerPrivate.Length==0,"non-creator invites another member with the correct entry target");
            Check(Code(Commit(b.Directory!,MeshGovernance.Head(approved)))==200,"creator absence does not prevent another member approving");
            var three=b.Directory!;a.Directory=three;c.Directory=three;
            using(var exchange=new PairKeyExchange()){
                var proven=MeshRejoin.Create(MeshRejoin.Retain(b),"123456",exchange)!;
                var replacing=CopyMesh(a);var replacement=MeshIdentity.Replace(replacing,b.Self);
                var otherManager=CopyMesh(c);otherManager.Directory=replacing.Directory;
                Check(MeshRejoin.Resolve(otherManager,proven,"123456",exchange.Commitment)==replacement.Member,"different manager recognizes prior rejoin lineage without a creator-local journal");
                var binding=new DeviceProfile{Mesh=otherManager,SavedPeerEntryNetwork=otherManager.Pair.Network,SavedNetworkSettings=new(){ExistingEntries=[new(b.Self.Slot,"203.0.113.5:44680")]}};
                Check(ControlWorker.RuntimeEntries(binding).Single().PeerSlot==replacement.Member.Slot&&binding.SavedNetworkSettings.ExistingEntries.Single().PeerSlot==b.Self.Slot,"another manager's replacement updates runtime entry binding without editing saved settings");
                MeshIdentity.Revoke(otherManager,replacement.Member.Slot);
                Check(MeshRejoin.Resolve(otherManager,proven,"123456",exchange.Commitment)==null,"explicit removal invalidates cross-member rejoin lineage");
            }
            using(var exchange=new PairKeyExchange()){
                var leavingCreator=CopyMesh(a);leavingCreator.Directory=MeshGovernance.Change(leavingCreator,"leave",1);
                var credential=MeshRejoin.Retain(leavingCreator)!;
                var proof=MeshRejoin.Create(credential,"654321",exchange)!;
                var inviting=CopyMesh(b);inviting.Directory=leavingCreator.Directory;
                var returning=MeshRejoin.Resolve(inviting,proof,"654321",exchange.Commitment);
                Check(returning==a.Self&&MeshGovernance.CurrentSlot(inviting.Directory!,1)==0,"voluntary exit retains rejoin proof without treating the departed entry as online membership");
                var returned=MeshIdentity.Replace(inviting,returning!,a.LocalIp);
                Check(returned.Member.Slot!=1&&MeshAddressing.Address(a.Pair.Network,returned.Member)==a.LocalIp,"explicit reapproval preserves a departed device's custom IP with a fresh slot and key");
                Check(MeshRejoin.Resolve(inviting,proof,"654321",exchange.Commitment)==returned.Member,"old proof follows a confirmed readmission without adding duplicates");
                Invalid(()=>MeshIdentity.Replace(inviting,a.Self,a.LocalIp),"one voluntary-exit address claim cannot be consumed twice");
                MeshIdentity.Revoke(inviting,returned.Member.Slot);
                Check(MeshRejoin.Resolve(inviting,proof,"654321",exchange.Commitment)==null,"explicit removal cuts the complete readmission lineage");
            }
            var branchA=CopyMesh(a);var branchB=CopyMesh(b);
            _=Guest(branchA);_=Guest(branchB);
            int[] codes=await Task.WhenAll(Task.Run(()=>Code(Commit(branchA.Directory!,MeshGovernance.Head(three)))),Task.Run(()=>Code(Commit(branchB.Directory!,MeshGovernance.Head(three)))));
            Check(codes.Order().SequenceEqual(new[]{200,409}),"concurrent admissions accept exactly one proposal, rejecting duplicate slot/IP");
            var winning=codes[0]==200?branchA.Directory!:branchB.Directory!;
            Check(Code(Commit(winning,MeshGovernance.Head(three)))==200,"lost commit response retries idempotently");
            Invalid(()=>MeshIdentity.ValidateSuccessor(codes[0]==200?branchB.Directory!:branchA.Directory!,winning),"clients reject divergent signed histories");
            var unauthorized=new DefaultHttpContext();unauthorized.Request.Headers.Authorization="Bearer "+new string('A',64);
            Check(Code(registry.Membership(unauthorized,a.Pair.Network,new(MeshGovernance.Head(winning),winning)))==401,"network secret still required for membership access");
            Check(Code(registry.Directory(unauthorized,a.Pair.Network,winning with{Governance="not-a-proof"}))==401,"replication authenticates before attempting expensive governance parsing");
            b.Directory=winning;
            MeshIdentity.Revoke(b,1);
            Check(Code(Commit(b.Directory!,MeshGovernance.Head(winning)))==200,"ordinary member can remove the original creator");
            var removed=b.Directory!;a.Directory=removed;
            Check(!a.CanManage,"retaining the root private key does not retain management rights after removal");
            Invalid(()=>MeshIdentity.Issue(a),"removed creator cannot issue a new equal-membership admission");
            Check(Code(registry.Directory(context,a.Pair.Network,legacy))==409,"legacy root directory cannot bypass the new membership API");
            Check(Code(registry.Directory(context,a.Pair.Network,branchA.Directory!))==409||MeshGovernance.Head(branchA.Directory!)==MeshGovernance.Head(winning),"uncommitted branch cannot enter via directory replication");
            var peerLane=new MeshPeerSynchronization(c);
            peerLane.Merge(new(removed,[]));
            Check(peerLane.DirectoryRevision==three.Revision,"peer signature cannot install an unconfirmed governance change");
            peerLane.Merge(new(removed,[]),true);
            Check(peerLane.DirectoryRevision==removed.Revision,"authenticated coordinator installs the committed successor");peerLane.Dispose();
            var unknown=CopyMesh(b);_=Guest(unknown);
            Check(Code(registry.Directory(context,a.Pair.Network,unknown.Directory!))==409,"forwarding endpoint cannot publish uncommitted future governance");
            var returnedA=MeshRejoin.Retain(a)!;returnedA.Validate();
            Check(returnedA.Member.Slot==1&&returnedA.Directory!=null,"creator can retain a former-member proof for explicit re-admission");
            c.Directory=removed;
            byte[] bc=MeshIdentity.SharedKey(b,c.Self),cb=MeshIdentity.SharedKey(c,b.Self);
            Check(bc.SequenceEqual(cb),"remaining members retain symmetric encrypted data keys after creator removal");
            Invalid(()=>MeshIdentity.ValidateDirectory(removed with{Closed=true},a.Pair.Network,a.OwnerKey),"unsigned closure flag rejected");
            Invalid(()=>MeshIdentity.ValidateDirectory(removed with{Members=removed.Members[..^1]},a.Pair.Network,a.OwnerKey),"member table tampering rejected against signed history");
            var history=MeshGovernance.Unpack(removed.Governance!);
            var tampered=history with{Changes=history.Changes.Select((change,i)=>i==0?change with{Actor=254}:change).ToArray()};
            Invalid(()=>MeshIdentity.ValidateDirectory(removed with{Governance=MeshGovernance.Pack(tampered)},a.Pair.Network,a.OwnerKey),"unauthorized actor in history rejected");
            var restarted=new MeshRegistry(root);
            Check(Code(restarted.Membership(context,a.Pair.Network,new(MeshGovernance.Head(winning),removed)))==200,"persisted coordinator accepts identical recovery after restart");
            var leaving=MeshGovernance.Change(b,"leave",b.Self.Slot);
            Check(Code(Commit(leaving,MeshGovernance.Head(removed)))==200,"member signs its own exit without deleting the network");
            c.Directory=leaving;
            var closed=MeshGovernance.Change(c,"close");
            Check(closed.Closed&&closed.Members.Length==0&&Code(Commit(closed,MeshGovernance.Head(leaving)))==200,"remaining member can dissolve network with a signed tombstone");
            Check(Code(Commit(unknown.Directory!,MeshGovernance.Head(removed)))==409,"closed network cannot be revived by a stale member branch");
            c.Directory=closed;Invalid(()=>MeshIdentity.Issue(c),"closed membership cannot authorize more devices");
            var one=MeshIdentity.Create("https://coordinator.example/","","faketcp");MeshGovernance.Enable(one);
            var last=MeshGovernance.Change(one,"leave",one.Self.Slot);Check(last.Closed&&last.Members.Length==0,"last member exit closes the network");
            var migration=MeshIdentity.Create("https://coordinator.example/","","faketcp");var old=migration.Directory!;_=Guest(migration);MeshGovernance.Enable(migration);
            MeshIdentity.ValidateSuccessor(migration.Directory!,old);Check(true,"offline legacy replica accepts migration anchored to a valid newer genesis");
            var settings=new DeviceProfile{Mesh=b,ConnectionSource="existing",ExistingEntries=[new(-1,"203.0.113.10:44680")],RejoinCredential=returnedA};
            var copied=ProfileChanges.Copy(settings);copied.Validate();Check(copied.Mesh!.CanManage&&copied.ExistingEntries.SequenceEqual(settings.ExistingEntries),"configuration round trip preserves equal membership and saved entries");
        }finally{Directory.Delete(root,true);}
        await GovernanceBounds();
        if(includeService)await GovernanceServiceRecovery();
        await GovernanceRunners();
        Console.WriteLine($"PASS {checks} equal membership checks");
    }
    static async Task GovernanceBounds()
    {
        var owner=MeshIdentity.Create("https://coordinator.example/","","faketcp");MeshGovernance.Enable(owner);
        var ticket=MeshIdentity.Issue(owner);
        for(int i=0;i<145;i++)ticket=MeshIdentity.Replace(owner,ticket.Member);
        string encoded=MeshIdentity.Export(ticket);var member=MeshIdentity.Import(encoded);
        Check(encoded.Length>65536&&encoded.Length<MeshGovernance.MaximumTicket&&member.CanManage,"long-lived membership exceeds old limits and still imports a complete authorized invitation");
        await using var router=new MeshRouter(CopyMesh(owner),new MemoryAdapter());
        var newTicket=MeshIdentity.Replace(owner,ticket.Member);router.ApplyDirectory(owner.Directory!);
        Check(router.Status().Any(p=>p.Slot==newTicket.Member.Slot),"router derives newly approved peer keys from the incoming history");
        var full=new ControlReply(true,"",new DeviceProfile{Mesh=owner},null,"",[]);
        using var wire=new MemoryStream();await ServiceProtocol.Write(wire,full,default);wire.Position=0;
        var restored=await ServiceProtocol.Read<ControlReply>(wire,default);
        Check(restored.Profile!.Mesh!.Directory!.Revision==owner.Directory!.Revision,"private IPC transports the bounded long-lived profile");
        try{await ServiceProtocol.Write(new MemoryStream(),new UiControlReply(false,new string('x',70000),null),default);throw new Exception("UI limit bypassed");}
        catch(IOException){Check(true,"public UI IPC retains its independent 64 KiB limit");}
        using var compressed=new MemoryStream();
        using(var writer=new System.IO.Compression.BrotliStream(compressed,System.IO.Compression.CompressionLevel.SmallestSize,true))writer.Write(new byte[MeshGovernance.MaximumProofBytes+1]);
        Invalid(()=>MeshGovernance.Unpack(Convert.ToBase64String(compressed.ToArray())),"compressed authorization cannot exceed the decompressed size budget");
        var before=owner.Directory!;var history=MeshGovernance.Unpack(before.Governance!);
        Invalid(()=>MeshIdentity.ValidateDirectory(before with{Governance=MeshGovernance.Pack(history with{Changes=[..history.Changes,history.Changes[0]]})},owner.Pair.Network,owner.OwnerKey),"duplicate operation and parent replay rejected");
        var poisoned=history.Changes.ToArray();poisoned[0]=poisoned[0] with{Parent=new string('0',64)};
        Invalid(()=>MeshIdentity.ValidateDirectory(before with{Governance=MeshGovernance.Pack(history with{Changes=poisoned})},owner.Pair.Network,owner.OwnerKey),"cached head cannot conceal a tampered earlier history prefix");
    }
}
