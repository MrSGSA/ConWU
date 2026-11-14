using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
int checks=0;
void Check(bool ok,string name){if(!ok)throw new Exception(name);checks++;Console.WriteLine("PASS "+name);}
async Task Until(Func<bool> ready,string name,int timeout=12000){long end=Environment.TickCount64+timeout;while(!ready()){if(Environment.TickCount64>=end)throw new TimeoutException(name);await Task.Delay(30);}Check(true,name);}
MeshProfile Guest(MeshProfile owner)=>MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)));
byte[] Packet(string source,string target){byte[] b=new byte[128];b[0]=0x45;b[8]=64;b[9]=17;BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2),(ushort)b.Length);IPAddress.Parse(source).GetAddressBytes().CopyTo(b,12);IPAddress.Parse(target).GetAddressBytes().CopyTo(b,16);BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(20),45000);BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(22),45001);BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(24),108);uint sum=0;for(int i=0;i<20;i+=2)sum+=BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(i));while(sum>>16!=0)sum=(sum&65535)+(sum>>16);BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(10),(ushort)~sum);return b;}
int FreePort(){var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();return port;}
DeviceProfile Profile(MeshProfile mesh,bool enabled=false){var p=new DeviceProfile{Mesh=mesh,Enabled=enabled,CoordinatorRoleVersion=1,ConnectionSource="existing",ExistingEntries=[new(mesh.IsOwner?0:mesh.IntroducerSlot,"203.0.113.7:49170")]};p.SelectTransport("tcp-only");return p;}
string root=Path.GetFullPath("artifacts/release-1.4.3/lifecycle-tests/"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
string sid=WindowsIdentity.GetCurrent().User!.Value;

// Real authenticated mesh control/metadata, with memory adapters. The routers
// exchange on loopback and never create a production NIC, mapping or firewall.
{
    var owner=MeshIdentity.Create("","","tcp",direct:true,pairwise:true);var guest=Guest(owner);string identity=JsonSerializer.Serialize(guest);
    var a=new Adapter();var b=new Adapter();
    await using var host=new MeshRouter(owner,a);await using var client=new MeshRouter(guest,b);
    using var hostSync=new MeshPeerSynchronization(owner);using var guestSync=new MeshPeerSynchronization(guest);hostSync.Attach(host);guestSync.Attach(client);
    host.SetCandidate(guest.Self.Slot,client.LocalEndpoint,"guest","loopback lifecycle fixture");client.SetCandidate(owner.Self.Slot,host.LocalEndpoint,"host","loopback lifecycle fixture");
    await Until(()=>host.HasHealthyPath(guest.Self.Slot)&&client.HasHealthyPath(owner.Self.Slot),"both peers establish authenticated control paths");
    b.Outgoing.Add(Packet(guest.LocalIp,owner.LocalIp));a.Outgoing.Add(Packet(owner.LocalIp,guest.LocalIp));
    await Until(()=>a.Received.Count==1&&b.Received.Count==1,"application packets work in both directions before disconnect");
    client.SetDataEnabled(false);
    long expiry=DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeSeconds();
    guestSync.Publish(new(guest.Self.Slot,guest.Self.Device,1,expiry,"203.0.113.20:45000","guest"){ConnectionPaused=true});
    long end=Environment.TickCount64+8000;
    while(Environment.TickCount64<end&&!host.Status().Single().ConnectionPaused){guestSync.Tick(Environment.TickCount64);hostSync.Tick(Environment.TickCount64);await Task.Delay(35);}
    Check(host.Status().Single().ConnectionPaused,"the host learns the guest's signed disconnected state");
    using(var cachedSync=new MeshPeerSynchronization(owner)){
        cachedSync.Merge(guestSync.Read()!);
        await using var lateRouter=new MeshRouter(owner,new Adapter());cachedSync.Attach(lateRouter);
        Check(lateRouter.Status().Single().ConnectionPaused,"a router created after discovery inherits the verified disconnected state");
    }
    int reads=a.Reads+b.Reads;for(int i=0;i<10;i++){b.Outgoing.Add(Packet(guest.LocalIp,owner.LocalIp));a.Outgoing.Add(Packet(owner.LocalIp,guest.LocalIp));}
    await Until(()=>a.Reads+b.Reads>=reads+20,"disconnected adapters drain application packets instead of retaining stale traffic");
    await Task.Delay(150);
    Check(a.Received.Count==1&&b.Received.Count==1,"neither direction forwards application data while disconnected");
    hostSync.Publish(new(owner.Self.Slot,owner.Self.Device,2,expiry,"203.0.113.21:45001","host"));
    end=Environment.TickCount64+12000;bool updated=false;
    while(Environment.TickCount64<end&&!updated){hostSync.Tick(Environment.TickCount64);guestSync.Tick(Environment.TickCount64);updated=guestSync.Read()!.Nodes.Any(n=>n.Slot==owner.Self.Slot&&MeshMetadata.Open(guest,owner.Self,n).Endpoint=="203.0.113.21:45001");await Task.Delay(35);}
    Check(updated&&host.HasHealthyPath(guest.Self.Slot)&&client.HasHealthyPath(owner.Self.Slot),"host address changes and authenticated keepalive continue during disconnect");
    client.SetDataEnabled(true);guestSync.Publish(new(guest.Self.Slot,guest.Self.Device,2,expiry,"203.0.113.20:45000","guest"));
    end=Environment.TickCount64+8000;
    while(Environment.TickCount64<end&&host.Status().Single().ConnectionPaused){guestSync.Tick(Environment.TickCount64);hostSync.Tick(Environment.TickCount64);await Task.Delay(35);}
    Check(!host.Status().Single().ConnectionPaused,"reconnect restores the host's forwarding permission through signed metadata");
    b.Outgoing.Add(Packet(guest.LocalIp,owner.LocalIp));a.Outgoing.Add(Packet(owner.LocalIp,guest.LocalIp));
    await Until(()=>a.Received.Count==2&&b.Received.Count==2,"the original network resumes bidirectional application data without pairing");
    Check(JsonSerializer.Serialize(guest)==identity,"disconnect and reconnect retain the exact membership, keys and virtual IP");
}

// Persistent UI state and an actual production runner, with an injected memory
// adapter and empty discovery. No installed service or real gateway is touched.
{
    var owner=MeshIdentity.Create("","","tcp",direct:true,pairwise:true);var guest=Guest(owner);
    var store=new ProfileStore(Path.Combine(root,"pause"));store.AuthorizeUiUser(sid);store.Save(Profile(guest,true));
    var adapter=new Adapter();
    var runtime=new MeshRuntimeServices(m=>new DirectMeshDiscovery(m),_=>Task.FromResult<IPacketAdapter>(adapter),
        (_,_,_)=>throw new Exception("unexpected gateway mapping"),_=>throw new Exception("unexpected transport"),
        (_,_,token)=>Task.Delay(Timeout.Infinite,token),(_,_,_)=>{},(_,_)=>{},Path.Combine(store.DirectoryPath,"sessions")) {
        ResolveEntries=(_,_,_)=>Task.FromResult(Array.Empty<EntryResolution>()),NetworkWake=()=>new MeshNetworkWake(false)
    };
    var worker=new ControlWorker(store,runtime,isolatedNetwork:true);
    string before;
    using(worker){worker.StartLocal();
    await Until(()=>worker.SingleUiSnapshot().Adapter?.Loaded==true,"the production runner opens the injected adapter");
    before=JsonSerializer.Serialize(store.Load().Mesh);
    var paused=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("disconnect",ExpectedNetwork:guest.Pair.Network)),sid,default);
    Check(paused.Ok&&paused.Status!.NetworkPaused&&!paused.Status.NetworkEnabled&&store.Load() is {Enabled:true,ConnectionPaused:true}&&!adapter.Stopped,"disconnect persists maintenance mode and keeps existing network resources");
    var stale=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("reconnect",ExpectedNetwork:Guid.NewGuid().ToString("N"))),sid,default);
    Check(!stale.Ok&&store.Load().ConnectionPaused,"a stale tab cannot reconnect a different network");
    var resumed=await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("reconnect",ExpectedNetwork:guest.Pair.Network)),sid,default);
    Check(resumed.Ok&&!resumed.Status!.NetworkPaused&&resumed.Status.NetworkEnabled&&JsonSerializer.Serialize(store.Load().Mesh)==before&&!adapter.Stopped,"reconnect resumes the same resources and persisted network identity");
    await worker.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("disconnect",ExpectedNetwork:guest.Pair.Network)),sid,default);
    await worker.StopLocal();Check(adapter.Stopped,"explicit backend shutdown still joins maintenance resources");
    }
    var nextAdapter=new Adapter();var restartedRuntime=runtime with{Adapter=_=>Task.FromResult<IPacketAdapter>(nextAdapter)};
    using var restarted=new ControlWorker(new ProfileStore(store.DirectoryPath),restartedRuntime,isolatedNetwork:true);restarted.StartLocal();
    await Until(()=>restarted.SingleUiSnapshot().Adapter?.Loaded==true,"a backend restart restores the maintenance resources");
    Check(restarted.SingleUiSnapshot() is {NetworkPaused:true,NetworkEnabled:false},"a saved disconnect never reconnects application data implicitly at startup");
    var restored=await restarted.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("reconnect",ExpectedNetwork:guest.Pair.Network)),sid,default);
    Check(restored.Ok&&!restored.Status!.NetworkPaused&&JsonSerializer.Serialize(store.Load().Mesh)==before,"explicit reconnect after restart retains membership and the virtual IP");
    await restarted.StopLocal();
}

// The guest exits while its host is offline. Its encrypted, durable outbox
// survives a backend restart, then uses the real TCP bootstrap and signed RPC.
{
    var owner=MeshIdentity.Create("","","tcp",direct:true,pairwise:true);var guest=Guest(owner);int port=FreePort();
    var hostStore=new ProfileStore(Path.Combine(root,"host"));hostStore.AuthorizeUiUser(sid);hostStore.Save(Profile(owner));
    var guestStore=new ProfileStore(Path.Combine(root,"guest"));guestStore.AuthorizeUiUser(sid);var p=Profile(guest);p.ExistingEntries=[new(guest.IntroducerSlot,$"203.0.113.7:{port}")];guestStore.Save(p);
    var notice=NetworkDeparture.Create(guest);notice.Validate(owner.OwnerKey);
    var editedMode=Profile(guest);editedMode.SelectTransport("https-only");
    Check(NetworkDepartureDelivery.Create(editedMode,"fixture",[]).Mode=="https","exit delivery follows the currently selected protocol rather than a historical invitation mode");
    var encoded=DirectPairWire.Encode(new DirectPairRequest(Guid.NewGuid().ToString("N"),"member-leave"){TargetNetwork=notice.Network,Departure=notice});
    Check(encoded.Length<=DirectPairWire.MaximumDatagram,"owner-certified leave proof fits the existing bounded bootstrap frame");
    bool forged=false;try{(notice with{Member=owner.Self}).Validate(owner.OwnerKey);}catch(CryptographicException){forged=true;}
    Check(forged,"a guest departure cannot delete the host or impersonate a different member");
    using(var leaving=new ControlWorker(guestStore,isolatedNetwork:true)){
        var result=await leaving.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:new("leave",ExpectedNetwork:guest.Pair.Network,ConfirmReplace:true)),sid,default);
        Check(result.Ok&&guestStore.Load() is {Mesh:null,Pair:null,RejoinCredential:null,Enabled:false},"an offline host cannot prevent local exit and permanent credential removal");
        Check(guestStore.ReadDepartures().Length==1&&hostStore.Load().Mesh!.Directory!.Members.Length==2,"an offline departure stays pending without falsely claiming host cleanup");
        await leaving.StopLocal();
    }
    using var hostWorker=new ControlWorker(hostStore,isolatedNetwork:true);
    var adapter=new Adapter();await using var router=new MeshRouter(owner,adapter){DirectPairing=hostWorker.HandleDirectPairing};
    await using var listener=new StreamMeshTransport(owner,router.LocalEndpoint,true,port);
    var reopened=new ProfileStore(guestStore.DirectoryPath);
    var deliveryRuntime=MeshRuntimeServices.Default with{ResolveEntries=(_,_,_)=>Task.FromResult(new[]{new EntryResolution(1,guest.IntroducerSlot,"fixture",[$"127.0.0.1:{port}"],"")})};
    using(var brokenNative=new ControlWorker(reopened,deliveryRuntime with{Transport=_=>throw new InvalidOperationException("fixture native launch failure")})){
        brokenNative.StartLocal();await Task.Delay(200);await brokenNative.StopLocal();
        Check(reopened.ReadDepartures().Length==1,"a failing native helper retains the exit notification and cannot break backend shutdown");
    }
    using(var dispatcher=new ControlWorker(reopened,deliveryRuntime)){
        dispatcher.StartLocal();
        await Until(()=>reopened.ReadDepartures().Length==0,"a restarted backend automatically redelivers and clears a confirmed leave notification",22000);
        Check(hostStore.Load().Mesh!.Directory is {Members.Length:1} directory&&directory.Members[0].Slot==owner.Self.Slot,"the host retains an empty network with no guest member");
        Check(hostStore.Load().Mesh!.Pair.Network==owner.Pair.Network,"guest exit preserves the host network identity for future pairing");
        await dispatcher.StopLocal();
    }
    var pending=new NetworkDepartureReceipt(guest.Pair.Network,notice.Nonce,guest.Self.Slot,2,"");
    bool fakeAck=false;try{pending.Validate(owner.OwnerKey,notice);}catch(CryptographicException){fakeAck=true;}
    Check(fakeAck,"an unsigned acknowledgement cannot discard a pending departure");
    var temporary=MeshIdentity.Create("","","tcp",direct:true);
    using var client=new DirectPairClient(_=>new StreamMeshTransport(temporary,new(IPAddress.Loopback,port),false,0,pairingBootstrap:true));
    using var deadline=new CancellationTokenSource(10000);var ack=await client.Depart(notice,owner.OwnerKey,deadline.Token);
    Check(ack.Slot==guest.Self.Slot&&hostStore.Load().Mesh!.Directory!.Members.Length==1,"replayed self-departures are idempotent after the member has already been removed");
}
{
    var damaged=new ProfileStore(Path.Combine(root,"damaged-outbox"));damaged.Save(new(){CoordinatorRoleVersion=1});
    await File.WriteAllTextAsync(Path.Combine(damaged.DirectoryPath,"pending-departures.dat"),"fixture corrupt protected data");
    using var dispatcher=new ControlWorker(damaged);dispatcher.StartLocal();await Task.Delay(100);await dispatcher.StopLocal();
    Check(File.Exists(Path.Combine(damaged.DirectoryPath,"pending-departures.dat")),"a damaged outbox is preserved for recovery without preventing service shutdown or updates");
}
Console.WriteLine($"PASS {checks} network lifecycle checks; loopback transports and isolated encrypted stores only");

sealed class Adapter:IPacketAdapter
{
    public readonly BlockingCollection<byte[]> Outgoing=new();public readonly ConcurrentQueue<byte[]> Received=new();public int Reads;public bool Stopped;
    public int Read(byte[] buffer)=>Read(buffer,default);
    public int Read(byte[] buffer,CancellationToken token){try{var p=Outgoing.Take(token);p.CopyTo(buffer,0);Interlocked.Increment(ref Reads);return p.Length;}catch(InvalidOperationException){return 0;}}
    public bool Write(byte[] packet){Received.Enqueue(packet);return true;}
    public void Stop(){Stopped=true;Outgoing.CompleteAdding();}
    public void Dispose()=>Stop();
}
