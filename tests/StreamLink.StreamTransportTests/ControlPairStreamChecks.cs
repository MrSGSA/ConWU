using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;

static class ControlPairStreamChecks
{
    public static async Task Run(Action<bool,string> check)
    {
        if(!OperatingSystem.IsWindows())return;
        string sid=System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value;
        string root=Path.Combine(Path.GetTempPath(),"conwu-stream-control-"+Guid.NewGuid().ToString("N"));
        string? before=Environment.GetEnvironmentVariable("STREAMLINK_PROFILE_ROOT");
        Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",root);
        try{foreach(string scenario in new[]{"tcp","https","https-wrong-approved-pin"}){
            string mode=scenario.StartsWith("https")?"https":"tcp";bool mismatch=scenario.EndsWith("pin");int port=FreePort();
            using var wrongKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);using var wrongCert=StreamCertificates.CreateServer(wrongKey,DateTimeOffset.UtcNow.AddDays(1));
            var workers=new List<ControlWorker>();
            try{
                for(int index=0;index<2;index++){
                    var store=new ProfileStore(Path.Combine(root,scenario,index.ToString()));store.AuthorizeUiUser(sid);
                    var profile=new DeviceProfile{DeviceName=index==0?"Host":"Guest",ListenPort=port+index*2,SourcePort=port+index*2+1};
                    ConnectionSettings.Apply(profile,new(PathSelection:TransportModes.Policy(mode),ListenPort:profile.ListenPort,SourcePort:profile.SourcePort){ConnectionSource="existing",DirectMode=true,DiscoveryMode="existing",ExistingEntries=index==0?[new(0,"203.0.113.25:"+port)]:[]});store.Save(profile);
                    var runtime=new MeshRuntimeServices(m=>new DirectMeshDiscovery(m),_=>Task.FromResult<IPacketAdapter>(new MemoryAdapter()),(_,_,_)=>throw new IOException("STUN forbidden"),r=>new StreamMeshTransport(r.Mesh,r.Server?r.Target:new(IPAddress.Loopback,port),r.Server,r.Port,()=>mismatch?wrongCert:StreamTransportIdentity.Get(),r.PairingBootstrap,r.ReserveEndpoint),(_,_,token)=>Task.Delay(Timeout.Infinite,token),(_,_,_)=>{},(_,_)=>{},Path.Combine(store.DirectoryPath,"sessions")){
                        Candidates=(_,_,_,_)=>throw new IOException("raw traversal forbidden"),NetworkWake=()=>new MeshNetworkWake(false),
                        ResolveEntries=(entries,_,_)=>Task.FromResult(entries.Select((e,i)=>new EntryResolution(e.PeerSlot,i,"地址",["203.0.113.25:"+port],"")).ToArray())
                    };
                    var worker=new ControlWorker(store,runtime);workers.Add(worker);worker.EnablePairNetworks();worker.StartLocal();
                }
                async Task<UiControlReply> Action(int node,string network,UiNetworkAction action){var response=await workers[node].HandleUi(new("network",OperationId:Guid.NewGuid(),Network:action){NetworkId=network},sid,default);return response;}
                async Task<UiStatusDto> State(int node)=>(await workers[node].HandleUi(new("status"),sid,default)).Status!;
                void Success(UiControlReply reply){if(!reply.Ok)throw new IOException(scenario+": "+reply.Error);}
                var created=await Action(0,"",new("create-direct",Mode:mode){Name="Protocol "+scenario,LocalEnrollment=true});Success(created);
                string hostId=created.Status!.SelectedNetworkId,networkId=created.Status.NetworkId;
                UiControlReply? issued=null;
                for(int n=0;n<80;n++){
                    issued=await Action(0,hostId,new("invite-compact",ExpectedNetwork:networkId));if(issued.Ok)break;await Task.Delay(50);
                }
                Success(issued!);string code=issued!.Status!.Pairing!.Code;
                check(CompactDirectCode.Import(code).Mode==mode,scenario+" service generates the correct sixteen-symbol protocol code");
                var joined=await Action(1,"",new("join-compact",Code:code){AutoConfigure=true});Success(joined);string guestId=joined.Status!.SelectedNetworkId;
                UiPairingDto? pairing=null;
                for(int n=0;n<100;n++){
                    Success(await Action(0,hostId,new("pair-poll")));Success(await Action(1,guestId,new("pair-poll")));
                    pairing=(await State(0)).Networks.Single().Status.Pairing;if(pairing?.Verification.Length==6)break;await Task.Delay(50);
                }
                if(pairing?.Verification.Length!=6)throw new IOException(scenario+" did not reach SAS approval");
                check((await State(1)).Networks.Single().Status.ReceivedNetworkSettings==null,scenario+" service retains no host settings before approval");
                Success(await Action(0,hostId,new("approve",ExpectedNetwork:networkId,Verification:pairing.Verification,Candidate:pairing.Candidate,ProposedIp:pairing.ProposedIp)));
                UiControlReply? polled=null;
                for(int n=0;n<100;n++){
                    polled=await Action(1,guestId,new("pair-poll"));if(!polled.Ok||polled.Status!.NetworkId.Length>0)break;await Task.Delay(50);
                }
                if(mismatch){
                    var state=await State(1);
                    check(polled?.Ok==false&&polled.Error.Contains("证书")&&state.Networks.Single().Status is {NetworkId:"",ReceivedNetworkSettings:null},"HTTPS approval with a different actual TLS pin is rejected before any network identity or settings are saved");
                }else{
                    Success(polled!);if(polled!.Status!.NetworkId!=networkId)throw new IOException(scenario+" approved identity not saved");
                    check(polled.Status.Settings?.PathSelection==TransportModes.Policy(mode)&&polled.Status.ReceivedNetworkSettings?.NetworkName=="Protocol "+scenario,scenario+" actual service approval imports the host configuration and chosen protocol");
                    bool connected=false;for(int n=0;n<160;n++){connected=(await State(0)).Aggregate?.ConnectedNetworks==1&&(await State(1)).Aggregate?.ConnectedNetworks==1;if(connected)break;await Task.Delay(50);}
                    check(connected,scenario+" approved control workflow reaches a bidirectional direct path through the production runner");
                }
            }finally{await Task.WhenAll(workers.Select(w=>w.StopLocal()));foreach(var worker in workers)worker.Dispose();}
        }}finally{Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",before);if(Directory.Exists(root))Directory.Delete(root,true);}
    }
    static int FreePort(){var value=new TcpListener(IPAddress.Loopback,0);value.Start();int p=((IPEndPoint)value.LocalEndpoint).Port;value.Stop();return p<65530?p:48440;}
}
