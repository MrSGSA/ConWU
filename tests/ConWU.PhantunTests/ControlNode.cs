using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

// Two isolated OS processes exercise real ControlWorker enrollment through the
// native carrier. Only public UI results leave the process; keys stay in its
// private temporary profile and are removed when the fixture stops.
static class ControlNode
{
    sealed record Input(bool Host,string Components,string HostIp,int Port,string Mode="phantun",bool Autonomous=false,int SourcePort=0,int LifetimeSeconds=300,bool CampusPunch=false,string[]? TcpStun=null,string Coordinator="",string CoordinatorPin="",bool AllowGatewayMapping=true,bool ForceAssistance=false,bool NativeDiagnostics=false);
    sealed class Adapter:IPacketAdapter
    {
        public bool Closed {get;private set;}
        public readonly BlockingCollection<byte[]> Outgoing=new();
        public readonly ConcurrentQueue<byte[]> Incoming=new();
        public int Read(byte[] buffer){if(!Outgoing.TryTake(out var packet,25))return 0;packet.CopyTo(buffer,0);return packet.Length;}
        public bool Write(byte[] packet){Incoming.Enqueue(packet);return true;}
        public void Dispose(){Closed=true;Outgoing.CompleteAdding();}
    }
    public static async Task Run()
    {
        var input=JsonSerializer.Deserialize<Input>(await Console.In.ReadLineAsync()??throw new IOException("fixture config missing"),new JsonSerializerOptions{PropertyNameCaseInsensitive=true})!;
        if(input.LifetimeSeconds is<30 or>600)throw new IOException("bounded control fixture lifetime required");
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(input.LifetimeSeconds));
        using var resolver=new ExistingEntryResolver();
        string root=Path.Combine(Path.GetTempPath(),"conwu-phantun-control-"+Guid.NewGuid().ToString("N"));
        string? previous=Environment.GetEnvironmentVariable("STREAMLINK_PROFILE_ROOT");
        Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",root);
        string user=OperatingSystem.IsWindows()?System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value:LinuxPlatform.UserIdentity;
        int entryProbes=0;var adapters=new ConcurrentQueue<Adapter>();var natives=new ConcurrentBag<PacketCarrierTransport>();ControlWorker? worker=null;
        try{
            var store=new ProfileStore(root);store.AuthorizeUiUser(user);
            var profile=new DeviceProfile{DeviceName=input.Host?"Phantun Host":"Phantun Guest",ListenPort=input.Port+(input.Host?0:2),SourcePort=input.Port+(input.Host?1:3)};
            if(input.Host&&input.SourcePort>0)profile.SourcePort=input.SourcePort;
            bool coordinated=input.Coordinator.Length>0;
            if(coordinated&&(!input.Autonomous||!TransportModes.TcpAssistance(input.Mode)))throw new IOException("coordinator assistance fixture requires an autonomous TCP carrier");
            ConnectionSettings.Apply(profile,new(input.Coordinator,input.CoordinatorPin,PathSelection:input.Mode+"-only",ListenPort:profile.ListenPort,SourcePort:profile.SourcePort){ConnectionSource=input.Autonomous?"custom":"existing",DirectMode=!coordinated,DiscoveryMode=input.Autonomous?coordinated?"coordinator":input.CampusPunch?"pkarr":"direct":"existing",TcpStun=input.TcpStun??Stun.TcpServers,ExistingEntries=input.Host&&!input.Autonomous?[new(0,input.HostIp+":"+input.Port)]:[]});store.Save(profile);
            Task<IPacketAdapter> OpenAdapter(){
                var adapter=new Adapter();adapters.Enqueue(adapter);return Task.FromResult<IPacketAdapter>(adapter);
            }
            async Task<IMapping> Probe(DeviceProfile p,Action<string> log,CancellationToken ct){
                Interlocked.Increment(ref entryProbes);
                if(!input.Autonomous)throw new IOException("existing-entry fixture forbids STUN or gateway mapping");
                if(!input.AllowGatewayMapping){
                    if(!TransportModes.TcpAssistance(input.Mode))throw new IOException("no-gateway fixture requires a TCP carrier");
                    var servers=PunchAssistProtocol.StunServer(p) is {} helper?new[]{helper}.Concat(p.OrderedTcp()).ToArray():p.OrderedTcp();
                    return input.Mode=="faketcp"?await FakeTcpSourceMapping.Create(p.ListenPort,servers,Console.Error.WriteLine,ct,allowGatewayMapping:false)
                        :await MimicMapping.Create(p.ListenPort,Console.Error.WriteLine,ct,servers,allowGatewayMapping:false,mode:input.Mode);
                }
                if(input.CampusPunch||coordinated)return await HostEntryProbe.Create(p,Console.Error.WriteLine,_=>{},ct);
                if(input.Autonomous&&input.Host)return await GatewayMapping.CreateTcp(p.SourcePort,p.ListenPort,Console.Error.WriteLine,ct,p.OrderedTcp(),p.ResourceScope,p.PortControlMapping);
                throw new IOException("fixture prohibits guest STUN");
            }
            var runtime=new MeshRuntimeServices(m=>m.Pair.Direct?new DirectMeshDiscovery(m):new MeshDiscoveryClient(m),_=>OpenAdapter(),Probe,r=>{
                try{
                if(input.ForceAssistance&&!r.Server&&r.Mapping==null)throw new IOException("isolated fixture forces the selected same-source assisted carrier");
                if(r.Mapping is FakeTcpSourceMapping fake)return new FakeTcpAssistTransport(input.Components,r.Folder,r.Mesh,r.Target,r.Server,fake);
                if(TransportModes.Stream(r.Mesh.Pair.Mode))return new StreamMeshTransport(r.Mesh,r.Target,r.Server,r.Port,StreamTransportIdentity.Get,r.PairingBootstrap,
                    allowListener:r.Server?()=>OperatingSystem.IsWindows()?WindowsHost.AllowStreamListener(r.Port,root):LinuxFirewall.AllowStreamListener(r.Port):null,sourceMapping:r.Mapping as ITcpSourceMapping);
                if(r.Mesh.Pair.Mode=="faketcp")return OperatingSystem.IsWindows()
                    ?new MeshTransport(input.Components,r.Folder,r.Mesh,r.Target,r.Server,r.Port,r.Mapping,"info",r.ReserveEndpoint)
                    :new LinuxMeshTransport(input.Components,r.Folder,r.Mesh,r.Target,r.Server,r.Port,r.Mapping,"info",r.ReserveEndpoint);
                var carrier=new PacketCarrierTransport(input.Components,r.Folder,r.Mesh,r.Target,r.Server,r.Port,"info",r.ReserveEndpoint,r.Mapping as MimicMapping);natives.Add(carrier);return carrier;
                }catch(Exception error){Console.Error.WriteLine("fixture transport startup: "+error);throw;}
            },(_,_,token)=>Task.Delay(Timeout.Infinite,token),(_,_,_)=>{},(_,_)=>{},Path.Combine(root,"sessions")){
                Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(null),NetworkWake=()=>new MeshNetworkWake(false),
                MimicPortSharing=input.CampusPunch||coordinated,TcpPortSharing=coordinated,
                TcpPairClient=async(folder,mesh,endpoint,log,ct,servers)=>await CoordinatedPairTransport.Create(input.Components,folder,mesh,endpoint,Console.Error.WriteLine,ct,servers,allowGatewayMapping:input.AllowGatewayMapping),
                MimicPairClient=async(folder,mesh,endpoint,log,ct,servers)=>await MimicMappedTransport.Create(input.Components,folder,mesh,endpoint,Console.Error.WriteLine,ct,servers,allowGatewayMapping:input.AllowGatewayMapping),
                ResolveEntries=(entries,mode,ct)=>input.Autonomous?resolver.Resolve(entries,mode,ct):Task.FromResult(entries.Select((e,i)=>new EntryResolution(e.PeerSlot,i,e.Source,[input.HostIp+":"+input.Port],"")).ToArray())
            };
            runtime=runtime with{ProfileAdapter=(_,_,_)=>OpenAdapter()};
            void Start(){worker=new(store,runtime);worker.EnablePairNetworks();worker.StartLocal();}
            Start();string selected="",network="";
            async Task<UiStatusDto> Status()=>(await worker!.HandleUi(new("status"),user,default)).Status!;
            string[] NativeLogs(){
                if(!input.NativeDiagnostics||!Directory.Exists(root))return [];
                var lines=new List<string>();
                foreach(string path in Directory.EnumerateFiles(root,"*.log",SearchOption.AllDirectories).Take(12))try{
                    using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);using var reader=new StreamReader(file);
                    lines.AddRange(reader.ReadToEnd().Split('\n').Where(line=>line.StartsWith("CONWU_RAW ")||line.StartsWith("CONWU_PHANTUN ")||line.Contains("SO ")||line.Contains("state")||line.Contains("[WARN]")||line.Contains("[ERROR]")||line.Contains("[FATAL]")).TakeLast(16));
                }catch(IOException){}
                return lines.TakeLast(80).ToArray();
            }
            object Public(UiStatusDto status){
                var s=status.Networks.FirstOrDefault()?.Status;var p=s?.Pairing;
                return new{entryProbes=Volatile.Read(ref entryProbes),activeAdapters=adapters.Count(a=>!a.Closed),paused=s?.NetworkPaused??false,connected=status.Aggregate?.ConnectedNetworks??0,networks=status.Networks.Length,members=s?.TotalPeers??0,network=s?.NetworkId??"",virtualIp=s?.VirtualIp??"",peerIp=s?.Peers.FirstOrDefault()?.VirtualIp??"",protocol=s?.Settings?.PathSelection??"",receivedSettings=s?.ReceivedNetworkSettings!=null,
                    nativeDiagnostics=NativeLogs(),code=p?.Code??"",verification=p?.Verification??"",candidate=p?.Candidate??"",proposedIp=p?.ProposedIp??"",nativePids=natives.Where(n=>!n.Exited).Select(n=>n.ProcessId).ToArray(),incoming=adapters.Sum(a=>a.Incoming.Count),state=s?.State??"",entry=s?.EntryPreparation,pkarr=s?.Pkarr,gatewayMappingAllowed=input.AllowGatewayMapping,logs=s?.Logs.TakeLast(input.CampusPunch||coordinated?16:4).ToArray()??[]};
            }
            void Print(object value)=>Console.WriteLine(JsonSerializer.Serialize(value));
            Print(new{eventName="ready",pid=Environment.ProcessId});
            while(await Console.In.ReadLineAsync().WaitAsync(deadline.Token) is string line){
                using var parsed=JsonDocument.Parse(line);var command=parsed.RootElement;string action=command.GetProperty("action").GetString()!;
                if(action=="stop"){Print(new{eventName="stopping"});return;}
                if(action=="status"){Print(new{eventName="status",state=Public(await Status())});continue;}
                if(action=="restart"){
                    await worker!.StopLocal();worker.Dispose();Start();Print(new{eventName="restarted",state=Public(await Status())});continue;
                }
                if(action=="send"){
                    var s=(await Status()).Networks.Single().Status;byte[] packet=Packet(s.VirtualIp,s.Peers.Single().VirtualIp);
                    adapters.Last(a=>!a.Closed).Outgoing.Add(packet);Print(new{eventName="sent"});continue;
                }
                UiNetworkAction request=action switch{
                    "create"=>new(coordinated?"create":"create-direct",Service:input.Coordinator,CertificatePin:input.CoordinatorPin,Mode:input.Mode){LocalEnrollment=true,Name="Native carrier approval"},
                    "invite"=>new("invite-compact",ExpectedNetwork:network),
                    "join"=>new("join-compact",Code:command.GetProperty("code").GetString()!){AutoConfigure=true},
                    "poll"=>new("pair-poll"),
                    "disconnect" or "reconnect"=>new(action,ExpectedNetwork:network),
                    "approve"=>new("approve",ExpectedNetwork:network,Verification:command.GetProperty("verification").GetString()!,Candidate:command.GetProperty("candidate").GetString()!,ProposedIp:command.GetProperty("proposedIp").GetString()!),
                    _=>throw new IOException("unknown fixture action")
                };
                var reply=await worker!.HandleUi(new("network",OperationId:Guid.NewGuid(),Network:request){NetworkId=selected},user,default);
                if(reply.Ok&&reply.Status!=null){selected=reply.Status.SelectedNetworkId;network=reply.Status.NetworkId;}
                Print(new{eventName=action,ok=reply.Ok,error=reply.Error,state=Public(reply.Status??await Status())});
            }
        }finally{
            if(worker!=null){await worker.StopLocal();worker.Dispose();}
            foreach(var native in natives)native.Dispose();
            Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",previous);
            if(Directory.Exists(root))Directory.Delete(root,true);
        }
    }
    static byte[] Packet(string source,string target){
        byte[] packet=new byte[1280];packet[0]=0x45;packet[8]=64;packet[9]=17;BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2),1280);
        IPAddress.Parse(source).GetAddressBytes().CopyTo(packet,12);IPAddress.Parse(target).GetAddressBytes().CopyTo(packet,16);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20),51001);BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22),51002);BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(24),1260);
        uint checksum=0;for(int i=0;i<20;i+=2)checksum+=BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(i));while(checksum>65535)checksum=(checksum&65535)+(checksum>>16);BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10),(ushort)~checksum);return packet;
    }
}
