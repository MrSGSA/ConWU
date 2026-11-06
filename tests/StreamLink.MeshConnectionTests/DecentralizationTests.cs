using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    // Production runners, crypto, packets and metadata lane; coordinator and
    // native physical transports are isolated substitutes, not a WAN test.
    sealed class ReplicaHub
    {
        readonly object gate = new();
        MeshDirectory? directory;
        readonly Dictionary<int, MeshEnvelope> nodes = [];
        public readonly ConcurrentDictionary<int, int> Saves = new();
        public readonly ConcurrentDictionary<int, bool> Unavailable = new();
        public readonly ConcurrentDictionary<int, MeshDirectory> Stale = new();
        public MeshDirectory? Directory { get { lock(gate) return directory; } }
        public void LoseTable() { lock(gate) { directory = null; nodes.Clear(); } }
        public void Install(MeshDirectory value) { lock(gate) { if(directory != null) MeshIdentity.ValidateSuccessor(value, directory); directory = value; } }
        public IMeshDiscovery Client(MeshProfile profile) => new ReplicaClient(this, profile);
        sealed class ReplicaClient(ReplicaHub hub, MeshProfile profile) : IMeshDiscovery
        {
            void Require(CancellationToken token) { token.ThrowIfCancellationRequested(); if(hub.Unavailable.GetValueOrDefault(profile.Self.Slot)) throw new IOException("isolated coordinator outage"); }
            public async Task SaveDirectory(MeshDirectory value, CancellationToken token)
            {
                await Task.CompletedTask;
                Require(token); MeshIdentity.ValidateDirectory(value, profile.Pair.Network, profile.OwnerKey);
                lock(hub.gate) { hub.Install(value); hub.Saves.AddOrUpdate(profile.Self.Slot, 1, (_, count) => count + 1); }
            }
            public async Task Publish(MeshAnnouncement node, CancellationToken token)
            {
                await Task.CompletedTask;
                Require(token); lock(hub.gate) {
                    var member = hub.directory?.Members.FirstOrDefault(m => m == profile.Self) ?? throw new IOException("member not registered");
                    var envelope = MeshMetadata.Seal(profile, node); MeshMetadata.ValidateEnvelope(profile.Pair.Network, member, envelope);
                    hub.nodes[member.Slot] = envelope;
                }
            }
            public async Task<MeshSnapshot?> Read(CancellationToken token)
            {
                await Task.CompletedTask;
                Require(token); lock(hub.gate) {
                    var table = hub.Stale.GetValueOrDefault(profile.Self.Slot) ?? hub.directory;
                    return table == null ? null : new MeshSnapshot(table,
                        hub.nodes.Values.Where(n => table.Members.Any(m => m.Slot == n.Slot && m.Device == n.Device)).ToArray());
                }
            }
            public void Dispose() { }
        }
    }
    static MeshProfile CopyMesh(MeshProfile profile) => ProfileChanges.Copy(new DeviceProfile { Mesh = profile }).Mesh!;
    static async Task Decentralization()
    {
        SynchronizationValidation();
        await AsymmetricSynchronization();
        var owner = MeshIdentity.Create("https://coordinator.example/", "", "faketcp");
        var first = Guest(owner); first.Directory = owner.Directory;
        var earlier = owner.Directory!;
        var second = Guest(owner); second.Directory = owner.Directory;
        var hub = new ReplicaHub(); hub.Install(owner.Directory!); hub.Stale[2] = earlier;
        string folder = Path.Combine(Path.GetTempPath(), "streamlink-replicas-" + Guid.NewGuid().ToString("N"));
        var persisted = new ConcurrentDictionary<int, MeshProfile>();
        var running = new Dictionary<int, (MeshRunner Runner, Task Task, CancellationTokenSource Stop, MemoryAdapter Adapter)>();
        var states = new ConcurrentDictionary<int, SessionStatus>();
        var configs = new Dictionary<int, DeviceProfile>();
        var logs = new ConcurrentQueue<string>();
        void Start(MeshProfile membership)
        {
            int slot = membership.Self.Slot;
            var mesh = CopyMesh(membership); persisted[slot] = CopyMesh(mesh);
            var profile = new DeviceProfile { Mesh = mesh, DeviceName = "node-" + slot, TraversalMode = "legacy" };
            configs[slot] = profile;
            var adapter = new MemoryAdapter(); var mapping = new Mapping();
            var services = new MeshRuntimeServices(hub.Client, _ => Task.FromResult<IPacketAdapter>(adapter),
                (_,_,_) => Task.FromResult<IMapping>(mapping), request => {
                    if(request.Server) { mapping.Change(request.Target); return new StubTransport(null); }
                    return new ForwardingTransport(request.Target, toleratePeerOffline: true);
                }, (_,_,ct) => Task.Delay(Timeout.Infinite, ct), (_,_,_) => {}, (_,_) => {}, folder) {
                Candidates = (_,_,_,_) => Task.FromResult<IMeshCandidateFactory?>(null), NetworkWake = () => new MeshNetworkWake(false)
            };
            var runner = new MeshRunner(profile, line => logs.Enqueue(slot + ": " + line), s => states[slot] = s,
                table => { var saved = CopyMesh(persisted[slot]); saved.Directory = table; persisted[slot] = saved; }, _ => {}, services);
            var stop = new CancellationTokenSource();
            running[slot] = (runner, runner.Run(stop.Token), stop, adapter);
        }
        async Task Halt(int slot)
        {
            var node = running[slot]; node.Stop.Cancel();
            try { await node.Task.WaitAsync(TimeSpan.FromSeconds(8)); } catch(OperationCanceledException) { } catch(MeshRevokedException) { }
            Check(node.Runner.CleanupComplete && node.Adapter.Disposed, "node " + slot + " releases its own resources");
            node.Stop.Dispose(); running.Remove(slot); states.TryRemove(slot, out _);
        }
        bool Connected(int slot, int peer) => states.TryGetValue(slot, out var s) && s.Peers?.Any(p => p.Slot == peer && p.Connected) == true;
        async Task Payload(int from, int to, string label)
        {
            long before = states[to].Peers!.Single(p => p.Slot == from).ReceivedBytes;
            running[from].Adapter.Outgoing.Add(Packet(persisted[from].LocalIp, persisted[to].LocalIp));
            await Until(() => states[to].Peers!.Single(p => p.Slot == from).ReceivedBytes >= before + 1280, label);
        }
        try {
            Start(owner); Start(first); Start(second);
            await Until(() => Connected(1,2) && Connected(1,3) && Connected(2,3) && Connected(3,2), "three coordinated runners establish independent authenticated links", 25000);
            Check(persisted[2].Directory?.Revision == owner.Directory!.Revision, "peer synchronization persists the newer table despite a stale coordinator view");
            await Until(() => hub.Saves.ContainsKey(2) && hub.Saves.ContainsKey(3), "non-owner replicas republish signed membership without administrator keys", 7000);
            Check(persisted[2].OwnerPrivate.Length == 0 && persisted[3].OwnerPrivate.Length == 0, "replication never grants administrative credentials");
            hub.Stale.Clear(); await Halt(1);
            await Until(() => !Connected(2,1) && !Connected(3,1) && Connected(2,3) && Connected(3,2), "creator goes offline while both remaining directions stay connected", 20000);
            await Payload(2,3,"full-size data reaches the other member with creator stopped");
            await Payload(3,2,"reverse payload does not require the creator or a relay");
            hub.Unavailable[2] = true;
            configs[3].DeviceName = "updated-through-peer"; running[3].Runner.RequestRetry();
            await Until(() => states[2].Peers!.Any(p => p.Slot == 3 && p.Name == "updated-through-peer"), "signed live metadata arrives over the peer link while this member cannot reach coordination", 22000);
            await Payload(2,3,"metadata recovery does not interrupt the healthy business path");
            hub.Unavailable.Clear(); await Halt(2); Start(persisted[2]);
            await Until(() => Connected(2,3) && Connected(3,2), "member restarts and reconnects through coordination without creator", 25000);
            await Payload(2,3,"restarted member uses its retained credential and IP");
            await Halt(2); await Halt(3);
            Check(persisted[2].Directory!.Members.Length == 3 && persisted[3].Directory!.Members.Length == 3, "all devices offline does not delete network identity or members");
            Start(persisted[3]); Start(persisted[2]);
            await Until(() => Connected(2,3) && Connected(3,2), "all-offline restart works with new physical loopback ports and unchanged membership", 25000);
            await Payload(3,2,"all-offline recovery delivers actual authenticated data");
            int previousSaves = hub.Saves.Values.Sum(); hub.LoseTable();
            running[2].Runner.RequestRetry(); running[3].Runner.RequestRetry();
            await Until(() => hub.Directory != null && hub.Saves.Values.Sum() > previousSaves, "surviving members restore missing coordination registration without creator", 15000);
            Check(hub.Directory!.Signature == owner.Directory!.Signature, "registration recovery forwards the original signed table unchanged");
            MeshIdentity.Revoke(owner, 2); hub.Install(owner.Directory!); running[2].Runner.RequestRetry();
            await Until(() => running[2].Task.IsFaulted, "owner-signed revocation still terminates a member in the replicated network", 15000);
            Check(running[2].Task.Exception!.GetBaseException() is MeshRevokedException && persisted[2].Directory!.Revision == owner.Directory!.Revision && !persisted[2].Directory!.Members.Contains(persisted[2].Self), "revocation high-water mark is persisted before shutdown");
            await Halt(2);
            int starts = 0;
            var refused = new MeshRunner(new(){Mesh=CopyMesh(persisted[2])}, _=>{}, _=>{}, _=>{}, _=>{},
                new(_=>{starts++;throw new Exception("must not contact coordination");}, _=>throw new Exception(), (_,_,_)=>throw new Exception(), _=>throw new Exception(), (_,_,_)=>throw new Exception(), (_,_,_)=>{}, (_,_)=>{}, folder));
            try { await refused.Run(default); throw new Exception("revoked restart admitted"); } catch(MeshRevokedException) { }
            Check(starts == 0, "persisted revocation blocks restart before network resources or stale re-registration");
        } catch {
            foreach(string line in logs.TakeLast(35)) Console.WriteLine(line);
            throw;
        } finally {
            foreach(int slot in running.Keys.ToArray()) await Halt(slot);
            if(Directory.Exists(folder)) { foreach(string child in Directory.EnumerateDirectories(folder)) Directory.Delete(child); Directory.Delete(folder); }
        }
        Console.WriteLine($"PASS {checks} decentralized membership/runner checks; loopback only, physical NAT and streaming not certified");
    }
    static void SynchronizationValidation()
    {
        static void Reject(Action action) { try { action(); } catch(CryptographicException) { return; } throw new Exception("invalid synchronization was accepted"); }
        var owner = MeshIdentity.Create("https://coordinator.example/", "", "faketcp");
        var first = Guest(owner); var second = Guest(owner); first.Directory = second.Directory = owner.Directory;
        using var sync = new MeshPeerSynchronization(first);
        long revision = DateTime.UtcNow.Ticks, expires = DateTimeOffset.UtcNow.AddSeconds(90).ToUnixTimeSeconds();
        MeshEnvelope Entry(long version, string endpoint) => MeshMetadata.Seal(second, new(3,second.Self.Device,version,expires,endpoint,"second"));
        var oldTable = owner.Directory!;
        var newer = Entry(revision + 1,"203.0.113.3:45001");
        sync.Merge(new(oldTable,[newer])); sync.Merge(new(oldTable,[Entry(revision,"203.0.113.3:45000")]));
        Check(sync.Read()!.Nodes.Single().Revision == revision + 1, "out-of-order announcements cannot replace the latest address");
        sync.Merge(new(oldTable,[newer with {Signature=first.Self.Signature}]));
        Check(sync.Read()!.Nodes.Single() == newer, "another authorized member cannot forge a peer announcement");
        var expired = MeshMetadata.Seal(second,new(3,second.Self.Device,revision+2,DateTimeOffset.UtcNow.AddSeconds(-1).ToUnixTimeSeconds(),"203.0.113.3:45002","second"));
        sync.Merge(new(oldTable,[expired]));
        Check(sync.Read()!.Nodes.Single() == newer, "expired higher revision cannot replace a fresh authenticated address");
        Reject(()=>sync.Merge(new(oldTable with {Revision=oldTable.Revision+1},[])));
        Check(sync.DirectoryRevision == oldTable.Revision, "tampered membership never advances the high-water mark");
        MeshIdentity.Revoke(owner,3); sync.Merge(new(owner.Directory!,[])); sync.Merge(new(oldTable,[newer]));
        Check(sync.Read()!.Directory.Revision == owner.Directory!.Revision && sync.Read()!.Nodes.Length == 0, "revocation prunes cached announcements and old tables cannot resurrect them");
        var conflicting = CopyMesh(owner); conflicting.Directory = oldTable; MeshIdentity.Issue(conflicting);
        Reject(()=>sync.Merge(new(conflicting.Directory!,[])));
        Check(sync.DirectoryRevision == owner.Directory.Revision, "even valid signatures cannot silently replace a conflicting same-version directory");
        var resurrection = CopyMesh(conflicting);
        MeshIdentity.Issue(resurrection); // Signs a newer table reusing a revoked slot.
        Reject(()=>sync.Merge(new(resurrection.Directory!,[])));
        Check(sync.Read()!.Directory.Members.All(m=>m.Slot!=3), "newer revision cannot recycle a revoked credential");
    }
    static async Task AsymmetricSynchronization()
    {
        var owner=MeshIdentity.Create("https://coordinator.example/","","faketcp");var member=Guest(owner);member.Directory=owner.Directory;
        await using var left=new MeshRouter(CopyMesh(owner),new MemoryAdapter());
        await using var right=new MeshRouter(CopyMesh(member),new MemoryAdapter());
        using var toRight=new ForwardingTransport(right.LocalEndpoint,true);
        using var toLeft=new ForwardingTransport(left.LocalEndpoint,true);
        left.SetCandidate(2,toRight.ClientEndpoint,"right","");right.SetCandidate(1,toLeft.ClientEndpoint,"left","");
        await Until(()=>left.HasHealthyPath(2)&&right.HasHealthyPath(1),"two independent outbound paths authenticate for the same pair");
        using var a=new MeshPeerSynchronization(owner);using var b=new MeshPeerSynchronization(member);a.Attach(left);b.Attach(right);
        long expiry=DateTimeOffset.UtcNow.AddSeconds(90).ToUnixTimeSeconds();
        a.Publish(new(1,owner.Self.Device,1,expiry,"203.0.113.1:45000","left"));
        b.Publish(new(2,member.Self.Device,1,expiry,"203.0.113.2:45000","right"));
        long deadline=Environment.TickCount64+15000;
        while(Environment.TickCount64<deadline){a.Tick(Environment.TickCount64);b.Tick(Environment.TickCount64);if(a.Read()!.Nodes.Length==2&&b.Read()!.Nodes.Length==2)break;await Task.Delay(110);}
        Check(a.Read()!.Nodes.Length==2&&b.Read()!.Nodes.Length==2,"signed metadata crosses independently selected paths in both directions");
        Check(left.Status().Single().SentBytes==0&&right.Status().Single().ReceivedBytes==0,"replicated metadata does not count as streamed application data");
    }
    static async Task NetworkPause()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        var owner = MeshIdentity.Create("https://unavailable.example/", "", "faketcp"); Guest(owner); Guest(owner);
        var store = new ProfileStore(); store.Save(new DeviceProfile { Mesh=owner, Enabled=true, ConnectionSource="existing", ExistingEntries=[new(0,"https://entries.example/feed#streamlink")] });
        string sid=WindowsIdentity.GetCurrent().User!.Value; store.AuthorizeUiUser(sid);
        string before=JsonSerializer.Serialize(store.Load().Mesh);
        var adapter=new MemoryAdapter();
        var services=new MeshRuntimeServices(m=>new OwnerOnlyDiscovery(m),_=>Task.FromResult<IPacketAdapter>(adapter),
            (_,_,_)=>throw new Exception("explicit entry fixture cannot probe"),_=>throw new Exception("no resolved fixture endpoint"),
            (_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},Path.Combine(ProfileStore.Root,"sessions")) {
            Candidates=(_,_,_,_)=>throw new Exception("explicit entry fixture cannot gather candidates"),
            ResolveEntries=(_,_,_)=>Task.FromResult(Array.Empty<EntryResolution>()),NetworkWake=()=>new MeshNetworkWake(false)
        };
        using(var worker=new ControlWorker(services)) {
            worker.StartLocal();
            await Until(()=>worker.Handle(new("status")).GetAwaiter().GetResult().Status?.Adapter?.State=="Opened","actual isolated runner starts before temporary departure");
            string settings=JsonSerializer.Serialize((await worker.HandleUi(new("status"),sid,default)).Status!.Settings);
            var ambiguous=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("leave",ExpectedNetwork:owner.Pair.Network,ConfirmReplace:true)),sid,default);
            Check(!ambiguous.Ok && JsonSerializer.Serialize(store.Load().Mesh)==before, "ambiguous owner leave cannot accidentally revoke the whole network");
            var paused=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("pause-network",ExpectedNetwork:owner.Pair.Network,ConfirmReplace:true)),sid,default);
            Check(paused.Ok && !store.Load().Enabled && JsonSerializer.Serialize(store.Load().Mesh)==before, "local departure keeps all memberships, administrator credentials and IPs without contacting unavailable coordination");
            Check(adapter.Disposed,"temporary departure joins the actual runner and releases its local adapter");
            Check(JsonSerializer.Serialize(paused.Status!.Settings)==settings, "local departure preserves all saved settings");
            var stale=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("pause-network",ExpectedNetwork:Guid.NewGuid().ToString("N"),ConfirmReplace:true)),sid,default);
            Check(!stale.Ok,"stale-tab pause cannot affect a different current network");
            await worker.StopLocal();
        }
        var member=Guest(owner); member.Directory=owner.Directory; store.Save(new DeviceProfile{Mesh=member,Enabled=false});
        using(var worker=new ControlWorker()) {
            var denied=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("delete-network",ExpectedNetwork:owner.Pair.Network,ConfirmReplace:true)),sid,default);
            Check(!denied.Ok && store.Load().Mesh!=null,"ordinary members cannot delete the network");
        }
        Console.WriteLine($"PASS {checks} explicit local departure / deletion checks");
    }
}
