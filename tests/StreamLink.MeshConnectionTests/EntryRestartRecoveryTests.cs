using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    static async Task EntryRestartRecovery()
    {
        await EntryRefreshAfterPathLoss();
        await EntryStartupBeforeHost();
        Console.WriteLine($"PASS {checks} entry restart/recovery checks; real encrypted loopback paths, simulated subscription and transport mappings; no installed service changes");
    }

    static async Task EntryRefreshAfterPathLoss()
    {
        var host=MeshIdentity.Create("","","faketcp",direct:true);
        var guest=Guest(host);guest.Directory=host.Directory;
        byte[] key=MeshIdentity.SharedKey(host,guest.Self);
        using var firstLink=new MeshLink(host.Self.Slot,guest.Self.Slot,key);
        using var restartedLink=new MeshLink(host.Self.Slot,guest.Self.Slot,key);
        CryptographicOperations.ZeroMemory(key);
        await using var firstPeer=new PeerEndpoint(firstLink);
        await using var restartedPeer=new PeerEndpoint(restartedLink);
        using var sink=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        const string seed="203.0.113.4:45000",before="203.0.113.5:45001",after="203.0.113.5:45002";
        const string subscription="txt://fixture.example#streamlink1";
        string current=before;
        bool oldAvailable=true;
        int reads=0,probes=0,factories=0,adapters=0;
        var profiles=new DeviceProfile {
            Mesh=guest,ConnectionSource="existing",DirectMode=true,EntryRefreshSeconds=3600,
            ExistingEntries=[new(ExistingEntry.Network,seed),new(ExistingEntry.NetworkOwner,subscription)],
            SavedNetworkSettings=new(){ConnectionSource="existing",DirectMode=true,EntryRefreshSeconds=3600,ExistingEntries=[new(ExistingEntry.NetworkOwner,subscription)]},
            JoinedEntryNetwork=guest.Pair.Network,JoinedEntrySources=[new(ExistingEntry.Network,seed),new(host.Self.Slot,subscription)]
        };
        // Use serialized credentials, just as a service restart would. No new
        // invitation or member approval is involved in either run below.
        string saved=JsonSerializer.Serialize(profiles);
        string folder=Path.Combine(Path.GetTempPath(),"conwu-entry-restart-"+Guid.NewGuid().ToString("N"));
        var targets=new ConcurrentQueue<string>();
        var transports=new ConcurrentBag<(string Target,ForwardingTransport Transport)>();
        var logs=new ConcurrentQueue<string>();
        SessionStatus? status=null;
        using var resolver=new ExistingEntryResolver((_,_)=>throw new Exception("fixture uses literal endpoints"),(_,_)=>{
            Interlocked.Increment(ref reads);return Task.FromResult(new[]{"streamlink1="+Volatile.Read(ref current)});
        });
        MemoryAdapter? adapter=null;
        var services=new MeshRuntimeServices(mesh=>new DirectMeshDiscovery(mesh),_=>{
            Interlocked.Increment(ref adapters);adapter=new();return Task.FromResult<IPacketAdapter>(adapter);
        },(_,_,_)=>{Interlocked.Increment(ref probes);throw new Exception("existing entries cannot start STUN or mapping");},request=>{
            if(request.Server)return new StubTransport(null);
            string target=request.Target.ToString();targets.Enqueue(target);
            var actual=target==after?restartedPeer.Endpoint:target==before&&Volatile.Read(ref oldAvailable)?firstPeer.Endpoint:(IPEndPoint)sink.Client.LocalEndPoint!;
            var transport=new ForwardingTransport(actual,toleratePeerOffline:true);transports.Add((target,transport));return transport;
        },(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},folder){
            ResolveEntries=resolver.Resolve,NetworkWake=()=>new MeshNetworkWake(false),
            Candidates=(_,_,_,_)=>{Interlocked.Increment(ref factories);throw new Exception("existing entries cannot start autonomous candidates");}
        };
        async Task Run(bool recover)
        {
            var profile=JsonSerializer.Deserialize<DeviceProfile>(saved)!;
            var runner=new MeshRunner(profile,logs.Enqueue,s=>Volatile.Write(ref status,s),_=>{},_=>{},services);
            using var stop=new CancellationTokenSource();var running=runner.Run(stop.Token);
            try {
                await Until(()=>Volatile.Read(ref status)?.Connected==true,recover?"saved subscription authenticates without a coordinator or fresh remote announcement":"same saved membership reconnects after a cold local restart",9000);
                if(recover){
                    var live=transports.Single(t=>t.Target==before&&!t.Transport.Disposed).Transport;
                    int priorReads=reads;
                    Volatile.Write(ref oldAvailable,false);live.Muted=true;
                    var clock=Stopwatch.StartNew();
                    await Until(()=>reads>priorReads,"loss of the proven path refreshes the subscription without waiting the one-hour polling interval or an OS network event",18000);
                    int staleRead=reads;
                    // The updater was late, so the first recovery query still
                    // returned the old tuple. It must not postpone the next
                    // read for the full configured hour or require user Retry.
                    Volatile.Write(ref current,after);
                    await Until(()=>reads>staleRead,"a delayed address publication is polled again within the bounded recovery interval",34000);
                    await Until(()=>Volatile.Read(ref status)?.Peers?.Single() is {Connected:true,OuterTarget:after},"changed external port reconnects the existing member without deleting or re-pairing the network",7000);
                    Check(live.Disposed&&adapters==1&&!adapter!.Disposed,"verified replacement retires the old transport while keeping the same adapter");
                    Console.WriteLine($"Entry restart recovery: {clock.ElapsedMilliseconds} ms including the unchanged 12-second health timeout");
                }
                int delivered=restartedPeer.DataPackets;
                adapter!.Outgoing.Add(Packet(guest.LocalIp,host.LocalIp));
                await Until(()=>restartedPeer.DataPackets>delivered,"reconnected membership delivers a complete authenticated IP packet");
                Check(JsonSerializer.Serialize(profile)==saved,"recovery leaves saved settings, network ID and member credentials unchanged");
                Check(probes==0&&factories==0&&targets.All(t=>t is seed or before or after),"only supplied entry candidates are dialed; no STUN, autonomous punching or protocol fallback");
            }catch{foreach(string line in logs)Console.WriteLine(line);throw;}
            finally{await Stop(running,stop);status=null;}
            Check(runner.CleanupComplete&&adapter!.Disposed&&transports.All(t=>t.Transport.Disposed),"stopped runner proves adapter and every candidate transport were released");
        }
        try{await Run(true);await Run(false);}
        finally{if(Directory.Exists(folder))Directory.Delete(folder,true);}
    }

    static async Task EntryStartupBeforeHost()
    {
        var owner=MeshIdentity.Create("","","faketcp",direct:true);
        var guest=Guest(owner);guest.Directory=owner.Directory;
        byte[] key=MeshIdentity.SharedKey(guest,owner.Self);
        using var peer=new MeshLink(guest.Self.Slot,owner.Self.Slot,key);CryptographicOperations.ZeroMemory(key);
        await using var endpoint=new PeerEndpoint(peer);
        var adapter=new MemoryAdapter();SessionStatus? status=null;int probes=0;bool published=false;
        string folder=Path.Combine(Path.GetTempPath(),"conwu-saved-entry-offline-"+Guid.NewGuid().ToString("N"));
        var profile=new DeviceProfile{Mesh=owner,ConnectionSource="existing",EntryRefreshSeconds=1,ExistingEntries=[new(guest.Self.Slot,"txt://fixture.example#streamlink1")]};
        var services=new MeshRuntimeServices(mesh=>new DirectMeshDiscovery(mesh),_=>Task.FromResult<IPacketAdapter>(adapter),(_,_,_)=>{probes++;throw new Exception("no autonomous probe");},
            r=>r.Server?new StubTransport(null):new ForwardingTransport(endpoint.Endpoint),(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},folder){
            Candidates=(_,_,_,_)=>throw new Exception("no candidate factory"),NetworkWake=()=>new MeshNetworkWake(false),
            ResolveEntries=(_,_,_)=>Task.FromResult(new[]{new EntryResolution(guest.Self.Slot,0,"TXT",Volatile.Read(ref published)?["203.0.113.6:45100"]:[],Volatile.Read(ref published)?"":"fixture source is not ready")})
        };
        var runner=new MeshRunner(profile,_=>{},s=>status=s,_=>{},_=>{},services);
        using var stop=new CancellationTokenSource();var running=runner.Run(stop.Token);
        try{
            await Until(()=>status?.Peers?.Single().Connection?.Phase=="EntryUnavailable","local startup before the peer and its subscription reports a recoverable missing entry");
            Volatile.Write(ref published,true);
            await Until(()=>status?.Connected==true,"later source availability connects saved membership without a fresh announcement, UI Retry or local network event",6000);
            Check(probes==0,"missing entry and later recovery cannot enable autonomous work in existing-entry mode");
        }finally{await Stop(running,stop);if(Directory.Exists(folder))Directory.Delete(folder,true);}
    }
}
