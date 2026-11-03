using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;
using System.Net;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task ExplicitReservationRecovery()
    {
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");
        var guest=Guest(owner);guest.Directory=owner.Directory;
        byte[] key=MeshIdentity.SharedKey(guest,owner.Self);
        using var link=new MeshLink(guest.Self.Slot,owner.Self.Slot,key);
        CryptographicOperations.ZeroMemory(key);
        await using var endpoint=new PeerEndpoint(link);
        var adapter=new MemoryAdapter();await using var router=new MeshRouter(owner,adapter);
        Check(router.ReserveTraversal(guest.Self.Slot,TraversalProfile.FakeTcpHttpSo),"autonomous candidate reserves preparation before explicit peer arrives");
        router.SetCandidate(guest.Self.Slot,endpoint.Endpoint,"explicit peer","late entry discovery");
        await Until(()=>router.UsesPath(guest.Self.Slot,endpoint.Endpoint),"a delayed explicit path authenticates while autonomous candidate is only preparing",4500);
        var context=new TraversalAttemptContext(owner.Pair.Network,owner.Self.Device,router.BootId,guest.Self.Device,Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),1,Guid.NewGuid(),1,TraversalProfile.FakeTcpHttpSo,true,true,Guid.NewGuid());
        await using var late=new UnregisteredPath(new(Guid.NewGuid(),context.AttemptId,Guid.NewGuid(),null,Guid.NewGuid(),new(IPAddress.Loopback,43001),new(IPAddress.Loopback,43002),context.Profile,PathQualification.MtuQualified));
        bool rejected=false;try{router.RegisterPath(guest.Self.Slot,late,context,1,TimeSpan.FromSeconds(8),1);}catch(IOException){rejected=true;}
        Check(rejected&&!late.Disposed&&!router.UsesManagedTransport(guest.Self.Slot)&&router.UsesPath(guest.Self.Slot,endpoint.Endpoint),"late autonomous registration cannot steal an explicit winner and leaves rejected resource caller-owned");
        Check(!router.ReserveTraversal(guest.Self.Slot,TraversalProfile.FakeTcpHttpSo),"new autonomous attempt cannot displace the explicit winner");
        Check(router.ReleaseTraversalReservation(guest.Self.Slot)&&router.UsesPath(guest.Self.Slot,endpoint.Endpoint),"cancelling unused preparation preserves explicit winner and its proof");
        adapter.Outgoing.Add(Packet(owner.LocalIp,guest.LocalIp));
        await Until(()=>endpoint.DataPackets==1,"full MTU application packet crosses the preserved explicit path");
        Check(!adapter.Disposed,"candidate cancellation does not recreate the virtual adapter");
        await ExplicitWinnerCancelsGather();
        await RemoteEntryPolicy();
        Console.WriteLine($"PASS {checks} explicit-entry/preparation reservation checks");
    }
    sealed class UnregisteredPath(ValidatedPathIdentity identity):IMeshDatagramPath
    {
        public ValidatedPathIdentity Identity=>identity;public bool Failed=>false;public bool Disposed;
        public bool TrySend(ReadOnlySpan<byte> data)=>false;
        public async ValueTask<ReadOnlyMemory<byte>> Receive(CancellationToken token){await Task.Delay(Timeout.Infinite,token);return ReadOnlyMemory<byte>.Empty;}
        public ValueTask DisposeAsync(){Disposed=true;return ValueTask.CompletedTask;}
    }
    sealed class PendingEntryFactory:IMeshCandidateFactory
    {
        public TraversalProfile[] Profiles=>[TraversalProfile.FakeTcpHttpSo];
        public int Gathered,Released;
        public async Task<IMeshCandidateResource> Gather(MeshMember peer,TraversalProfile profile,Guid attempt,CancellationToken token){
            Gathered++;try{await Task.Delay(Timeout.Infinite,token);throw new InvalidOperationException();}finally{Released++;}
        }
    }
    sealed class EntryControl:IMeshTraversalDiscovery
    {
        public Guid BootId{get;}=Guid.NewGuid();public bool SupportsTraversal=>true;
        public Task PublishTraversal(MeshTraversalMessage[] messages,CancellationToken token)=>Task.CompletedTask;
    }
    static async Task RemoteEntryPolicy()
    {
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");var guest=Guest(owner);guest.Directory=owner.Directory;
        var control=new EntryControl();var factory=new PendingEntryFactory();await using var router=new MeshRouter(owner,new MemoryAdapter(),control.BootId);
        await using var manager=new MeshTraversalManager(owner,router,control,factory,new(),_=>{},default);
        var caps=new MeshTraversalCapabilities(1,1,Guid.NewGuid(),[TraversalProfile.FakeTcpHttpSo]);
        var only=new MeshAnnouncement(guest.Self.Slot,guest.Self.Device,1,DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeSeconds(),"","peer",caps){ExistingEntryOnly=true};
        var sealedPolicy=MeshMetadata.Seal(guest,only);
        Check(MeshMetadata.Open(owner,guest.Self,sealedPolicy).ExistingEntryOnly,"entry-only policy survives authenticated encrypted peer announcement");
        var announcements=new Dictionary<int,MeshAnnouncement>{[guest.Self.Slot]=only};manager.Tick(announcements,"");
        Check(factory.Gathered==0&&!manager.Owns(guest.Self.Slot),"autonomous-mode peer does not gather or reserve for an entry-only device even with old advertised capabilities");
        announcements[guest.Self.Slot]=only with{ExistingEntryOnly=false,Revision=2};manager.Tick(announcements,"");
        Check(factory.Gathered==1,"manual return to autonomous policy enables an otherwise eligible attempt");
        announcements[guest.Self.Slot]=only with{Revision=3};manager.Tick(announcements,"");
        await Until(()=>{manager.Tick(announcements,"");return factory.Released==1&&!manager.Owns(guest.Self.Slot);},"new authenticated entry-only policy cancels and joins prior autonomous resources");
    }
    static async Task ExplicitWinnerCancelsGather()
    {
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");var guest=Guest(owner);guest.Directory=owner.Directory;
        var control=new EntryControl();var factory=new PendingEntryFactory();var adapter=new MemoryAdapter();
        await using var router=new MeshRouter(owner,adapter,control.BootId);
        await using var manager=new MeshTraversalManager(owner,router,control,factory,new(),_=>{},default);
        var caps=new MeshTraversalCapabilities(1,1,Guid.NewGuid(),[TraversalProfile.FakeTcpHttpSo]);
        var announcements=new Dictionary<int,MeshAnnouncement>{[guest.Self.Slot]=new(guest.Self.Slot,guest.Self.Device,1,DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeSeconds(),"","peer",caps)};
        manager.Tick(announcements,"");
        Check(factory.Gathered==1&&manager.Owns(guest.Self.Slot)&&!router.UsesManagedTransport(guest.Self.Slot),"scheduler reservation does not transfer data ownership during candidate gathering");
        byte[] key=MeshIdentity.SharedKey(guest,owner.Self);using var link=new MeshLink(guest.Self.Slot,owner.Self.Slot,key);CryptographicOperations.ZeroMemory(key);
        await using var endpoint=new PeerEndpoint(link);
        using var paths=new MeshPeerTransports(router,_=>new ForwardingTransport(endpoint.Endpoint),_=>{});
        paths.Update(guest.Self.Slot,endpoint.Endpoint.ToString(),"peer","");
        manager.ObserveLegacyPending(guest.Self.Slot,paths.HasPending);
        await Until(()=>{manager.Tick(announcements,"");return router.HasHealthyPath(guest.Self.Slot);},"independent explicit entry completes while scheduler owns pending SO");
        await Until(()=>{manager.Tick(announcements,"");return factory.Released==1&&!manager.Owns(guest.Self.Slot);},"explicit winner cancels and joins autonomous gathering before releasing reservation");
        paths.Update(guest.Self.Slot,endpoint.Endpoint.ToString(),"peer","");
        adapter.Outgoing.Add(Packet(owner.LocalIp,guest.LocalIp));await Until(()=>endpoint.DataPackets==1,"scheduler cleanup preserves actual full-size encrypted delivery on the explicit winner");
        Check(!adapter.Disposed&&factory.Gathered==1,"healthy explicit peer does not reopen native gathering or recreate Wintun");
    }
}
