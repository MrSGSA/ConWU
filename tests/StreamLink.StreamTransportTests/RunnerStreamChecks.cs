using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;

static class RunnerStreamChecks
{
    public static async Task Run(Action<bool,string> check)
    {
        if(!OperatingSystem.IsWindows())return;
        string sid=System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value;
        foreach(string mode in new[]{"tcp","https"}){
            string folder=Path.Combine(Path.GetTempPath(),"conwu-stream-runner-"+Guid.NewGuid().ToString("N"));
            using var signing=ECDsa.Create(ECCurve.NamedCurves.nistP256);using var certificate=StreamCertificates.CreateServer(signing,DateTimeOffset.UtcNow.AddDays(1));
            var host=MeshIdentity.Create("","",mode,direct:true,pairwise:true);
            if(mode=="https")host.Pair=host.Pair with{TransportKeyPin=StreamMeshTransport.CertificatePin(certificate)};
            var guest=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(host)));
            int port=FreePort(),hostDials=0,guestListeners=0,probes=0;
            using var adapterReady=new ManualResetEventSlim();
            var workers=new List<ControlWorker>();
            try{
                foreach(var (mesh,index) in new[]{(host,0),(guest,1)}){
                    string root=Path.Combine(folder,index.ToString());var store=new ProfileStore(root);store.AuthorizeUiUser(sid);
                    var profile=new DeviceProfile{Device=mesh.Self.Device,Mesh=mesh,DeviceName=index==0?"Host":"Guest",Enabled=true,ListenPort=port+index*2,SourcePort=port+index*2+1};profile.SelectTransport(TransportModes.Policy(mode));
                    var settings=new UiNetworkSettings(PathSelection:TransportModes.Policy(mode),ListenPort:profile.ListenPort,SourcePort:profile.SourcePort){ConnectionSource="existing",DirectMode=true,DiscoveryMode="existing",ExistingEntries=[new(index==0?0:ExistingEntry.NetworkOwner,"203.0.113.25:"+port)]};
                    ConnectionSettings.Apply(profile,settings);store.Save(profile);
                    var runtime=new MeshRuntimeServices(m=>new DirectMeshDiscovery(m),_=>Task.FromResult<IPacketAdapter>(new MemoryAdapter()),(_,_,_)=>{Interlocked.Increment(ref probes);throw new IOException("unexpected STUN");},r=>{
                        if(index==0&&!r.Server)Interlocked.Increment(ref hostDials);if(index==1&&r.Server)Interlocked.Increment(ref guestListeners);
                        return new StreamMeshTransport(r.Mesh,r.Server?r.Target:new(IPAddress.Loopback,port),r.Server,r.Port,()=>certificate,r.PairingBootstrap,r.ReserveEndpoint);
                    },(_,_,token)=>Task.Delay(Timeout.Infinite,token),(_,_,_)=>{},(_,_)=>{},Path.Combine(root,"sessions")){
                        Candidates=(_,_,_,_)=>throw new IOException("unexpected raw traversal"),NetworkWake=()=>new MeshNetworkWake(false),
                        ResolveEntries=(entries,_,_)=>Task.FromResult(entries.Select((e,i)=>new EntryResolution(e.PeerSlot,i,"地址",["203.0.113.25:"+port],"")).ToArray()),
                        ProfileAdapter=(_,_,token)=>Task.Factory.StartNew<IPacketAdapter>(()=>{if(index==1)adapterReady.Wait(token);return new MemoryAdapter();},CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default)
                    };
                    var worker=new ControlWorker(store,runtime);workers.Add(worker);worker.StartLocal();
                }
                // Simulate a slow synchronous device-driver startup, longer
                // than the UI's unchanged ten-second offline deadline.
                var delay=Stopwatch.StartNew();double worst=0;
                while(delay.ElapsedMilliseconds<11000){
                    var began=Stopwatch.GetTimestamp();var reply=await workers[1].HandleUi(new("status"),sid,default).WaitAsync(TimeSpan.FromSeconds(1));
                    worst=Math.Max(worst,Stopwatch.GetElapsedTime(began).TotalMilliseconds);
                    if(!reply.Ok||reply.Status?.ServiceReady!=true)throw new IOException("responsive backend was reported as offline during adapter startup");
                    await Task.Delay(200);
                }
                check(worst<1000,mode+" fresh control snapshots stay available throughout an eleven-second blocked adapter startup");
                adapterReady.Set();
                await Until(()=>workers.All(w=>w.SingleUiSnapshot().DirectPeers==1),mode+" runner establishes both ends after the delayed guest adapter is ready");
                check(hostDials==0&&guestListeners==0&&probes==0,mode+" host listens and guest dials without raw/STUN fallback or guest reachability requirements");
                check(workers.All(w=>w.SingleUiSnapshot().Peers.Single().ActualTransport==mode.ToUpperInvariant()),mode+" service snapshots retain the actual TCP/TLS carrier");
                // Drop only the guest's runtime and restart from the persisted
                // approved identity. Host listener and virtual IPs stay put.
                var stopped=await workers[1].HandleUi(new("stop",OperationId:Guid.NewGuid()),sid,default);check(stopped.Ok,mode+" guest runtime stops cleanly without changing its approved settings");
                var restarted=await workers[1].HandleUi(new("start",OperationId:Guid.NewGuid()),sid,default);check(restarted.Ok,mode+" guest runtime restarts with the saved transport and identity");
                await Until(()=>workers.All(w=>w.SingleUiSnapshot().DirectPeers==1),mode+" runner reconnects the same paired network after restart");
                check(workers[1].ProfileSnapshot().Mesh!.LocalIp==guest.LocalIp&&workers[1].ProfileSnapshot().TransportMode==mode,mode+" reconnect preserves virtual IP and protocol");
            }finally{
                adapterReady.Set();await Task.WhenAll(workers.Select(w=>w.StopLocal()));foreach(var worker in workers)worker.Dispose();
                if(Directory.Exists(folder))Directory.Delete(folder,true);
            }
        }
    }
    static async Task Until(Func<bool> ready,string detail){using var limit=new CancellationTokenSource(15000);try{while(!ready())await Task.Delay(50,limit.Token);}catch(OperationCanceledException){throw new IOException(detail);}}
    static int FreePort(){var value=new TcpListener(IPAddress.Loopback,0);value.Start();int p=((IPEndPoint)value.LocalEndpoint).Port;value.Stop();return p<65530?p:48440;}
}
