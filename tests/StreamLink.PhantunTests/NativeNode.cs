using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

// Invoked only by the namespace integration harness. Ephemeral test identities
// arrive on stdin; no production profile, TUN or configuration is opened.
static class NativeNode
{
    sealed record Input(bool Host,MeshProfile[] Meshes,string Components,string HostIp,int Port);
    sealed class Adapter(string local,string peer):IPacketAdapter
    {
        readonly BlockingCollection<byte[]> queue=new(256);
        readonly byte[] localIp=IPAddress.Parse(local).GetAddressBytes(),peerIp=IPAddress.Parse(peer).GetAddressBytes();
        long received,invalid;int disposed;
        public bool Offer(byte[] packet)=>queue.TryAdd(packet);
        public int Read(byte[] buffer){if(!queue.TryTake(out var packet,30))return 0;packet.CopyTo(buffer,0);return packet.Length;}
        public bool Write(byte[] packet){
            bool valid=packet.Length==1200&&packet.AsSpan(12,4).SequenceEqual(peerIp)&&packet.AsSpan(16,4).SequenceEqual(localIp)&&packet.AsSpan(44).IndexOfAnyExcept((byte)0x6d)<0;
            if(valid)Interlocked.Increment(ref received);else Interlocked.Increment(ref invalid);return valid;
        }
        public object Status()=>new{received=Interlocked.Read(ref received),invalid=Interlocked.Read(ref invalid)};
        public void Reset(){Interlocked.Exchange(ref received,0);Interlocked.Exchange(ref invalid,0);}
        public void Dispose(){if(Interlocked.Exchange(ref disposed,1)==0)queue.CompleteAdding();}
    }
    static void Print(object value)=>Console.WriteLine(JsonSerializer.Serialize(value));
    static string[] CarrierLogs(string root){
        var lines=new List<string>();if(!Directory.Exists(root))return [];
        foreach(string path in Directory.EnumerateFiles(root,"*.log",SearchOption.AllDirectories).Take(12)){
            try{using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);using var reader=new StreamReader(file);lines.AddRange(reader.ReadToEnd().Split('\n').TakeLast(6));}catch(IOException){}
        }return lines.ToArray();
    }
    public static async Task Run()
    {
        var input=JsonSerializer.Deserialize<Input>(await Console.In.ReadLineAsync()??throw new IOException("node config missing"),new JsonSerializerOptions{PropertyNameCaseInsensitive=true})!;
        if(input.Meshes.Length!=2||input.Meshes.Any(m=>!TransportModes.PacketCarrier(m.Pair.Mode)))throw new IOException("isolated two-network fixture required");
        string root=Path.Combine(Path.GetTempPath(),"conwu-phantun-node-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",root);
        var adapters=new Adapter[2];var routers=new MeshRouter[2];var transports=new IMeshTransport?[2];
        var native=new List<PacketCarrierTransport>();using var shared=new SharedMeshReceiver(root);
        int serverStarts=0;
        int Peer(int index)=>input.Meshes[index].Directory!.Members.Single(m=>m.Slot!=input.Meshes[index].Self.Slot).Slot;
        void OpenClient(int index){
            var mesh=input.Meshes[index];var transport=new PacketCarrierTransport(input.Components,root,mesh,new(IPAddress.Parse(input.HostIp),input.Port),false,input.Port,"info");
            native.Add(transport);transports[index]=transport;
            routers[index].SetCandidate(Peer(index),transport.ClientEndpoint,"test peer","native integration",true);
        }
        try{
            for(int index=0;index<2;index++){
                var mesh=input.Meshes[index];var member=mesh.Directory!.Members.Single(m=>m.Slot!=mesh.Self.Slot);
                string peer=MeshAddressing.Address(mesh.Pair.Network,member);
                adapters[index]=new(mesh.LocalIp,peer);routers[index]=new(mesh,adapters[index]);
                if(input.Host){
                    IMeshTransport Factory(MeshTransportRequest request){
                        serverStarts++;var carrier=new PacketCarrierTransport(input.Components,request.Folder,request.Mesh,request.Target,true,request.Port,"info");native.Add(carrier);return carrier;
                    }
                    transports[index]=shared.Acquire(new(root,mesh,routers[index].LocalEndpoint,true,input.Port,null,"info"){RetireEndpoint=routers[index].FailLegacyIngress},Factory,_=>false,p=>PairNetworkFrame.Authenticated(mesh,p.Span),_=>0);
                    routers[index].SetLegacyListenerControl(true);
                }else OpenClient(index);
            }
            object Status()=>new{host=input.Host,serverStarts,nativePids=native.Where(n=>!n.Exited).Select(n=>n.ProcessId).ToArray(),nativeFailures=native.Where(n=>n.Exited).Select(n=>n.FailureReason).ToArray(),carrierLogs=CarrierLogs(root),networks=Enumerable.Range(0,2).Select(i=>new{index=i,healthy=routers[i].HasHealthyPath(Peer(i)),adapter=adapters[i].Status(),transport=routers[i].Status().Single().ActualTransport,router=routers[i].Status().Single(),pump=routers[i].Completion.IsFaulted?routers[i].Completion.Exception?.ToString():"running"})};
            Print(new{eventName="ready",pid=Environment.ProcessId,status=Status()});
            while(await Console.In.ReadLineAsync() is string line){
                using var document=JsonDocument.Parse(line);var command=document.RootElement;string action=command.GetProperty("action").GetString()!;
                int index=command.TryGetProperty("index",out var item)?item.GetInt32():0;
                if(index is<0 or>1)throw new IOException("invalid fixture index");
                switch(action){
                    case "status":Print(new{eventName="status",status=Status()});break;
                    case "reset":foreach(var adapter in adapters)adapter.Reset();Print(new{eventName="reset"});break;
                    case "pause":{
                        if(input.Host)throw new IOException("guest pause only");
                        var endpoint=transports[index]?.ClientEndpoint;transports[index]?.Dispose();transports[index]=null;routers[index].FailLegacyTransport(Peer(index),endpoint);
                        Print(new{eventName="paused",index});break;
                    }
                    case "resume":{
                        if(input.Host||transports[index]!=null)throw new IOException("fixture already open");OpenClient(index);Print(new{eventName="resumed",index});break;
                    }
                    case "release":{
                        transports[index]?.Dispose();transports[index]=null;routers[index].FailLegacyListener();Print(new{eventName="released",index,status=Status()});break;
                    }
                    case "send":{
                        int seconds=command.GetProperty("seconds").GetInt32(),mbps=command.GetProperty("mbps").GetInt32();
                        if(seconds is<1 or>20||mbps is<1 or>50)throw new IOException("bounded fixture load required");
                        var mesh=input.Meshes[index];string peer=MeshAddressing.Address(mesh.Pair.Network,mesh.Directory!.Members.Single(m=>m.Slot!=mesh.Self.Slot));
                        var template=Packet(mesh.LocalIp,peer);long sent=0,rejected=0;double credit=0;
                        long began=Stopwatch.GetTimestamp(),credited=began;
                        while(Stopwatch.GetElapsedTime(began).TotalSeconds<seconds){
                            long now=Stopwatch.GetTimestamp();credit=Math.Min(credit+mbps*1e6/8/1200*Stopwatch.GetElapsedTime(credited,now).TotalSeconds,100);credited=now;
                            int count=(int)credit;credit-=count;
                            for(int p=0;p<count;p++){
                                byte[] packet=template.ToArray();BinaryPrimitives.WriteInt64LittleEndian(packet.AsSpan(28),sent+1);BinaryPrimitives.WriteInt64LittleEndian(packet.AsSpan(36),Stopwatch.GetTimestamp());
                                if(adapters[index].Offer(packet))sent++;else rejected++;
                            }
                            await Task.Delay(1);
                        }
                        double duration=Stopwatch.GetElapsedTime(began).TotalSeconds;
                        Print(new{eventName="sent",index,sent,rejected,seconds=duration,virtualIpMbps=sent*1200*8/duration/1e6});break;
                    }
                    case "stop":Print(new{eventName="stopping"});return;
                    default:throw new IOException("unknown fixture action");
                }
            }
        }finally{
            foreach(var transport in transports)transport?.Dispose();
            foreach(var router in routers)if(router!=null)await router.DisposeAsync();
            foreach(var adapter in adapters)adapter?.Dispose();
            shared.Dispose();
            if(OperatingSystem.IsLinux())LinuxFirewall.Recover();
            if(Directory.Exists(root))Directory.Delete(root,true);
        }
    }
    static byte[] Packet(string source,string target){
        byte[] bytes=new byte[1200];bytes[0]=0x45;bytes[8]=64;bytes[9]=17;BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2),1200);
        IPAddress.Parse(source).GetAddressBytes().CopyTo(bytes,12);IPAddress.Parse(target).GetAddressBytes().CopyTo(bytes,16);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(20),50001);BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(22),50002);BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(24),1180);bytes.AsSpan(44).Fill(0x6d);
        uint sum=0;for(int i=0;i<20;i+=2)sum+=BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(i));while(sum>65535)sum=(sum&65535)+(sum>>16);BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10),(ushort)~sum);return bytes;
    }
}
