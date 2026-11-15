using System.Net;

namespace StreamLink.Core;

public interface IPairTransportIdentity
{
    string PeerCertificatePin{get;}
    StreamConnectionStatus? StreamConnection{get;}
}

// One lifetime owns the retained source, its maintenance and the actual chosen
// carrier. Each adapter keeps its original wire and security implementation.
public sealed class CoordinatedPairTransport:IMappedMeshTransport,IMeshPunchTransport,IPairTransportIdentity
{
    readonly IMapping mapping;
    readonly IMeshTransport carrier;
    readonly CancellationTokenSource stop=new();
    readonly Task maintenance;
    int disposed;
    public IPEndPoint PublicEndpoint=>mapping.PublicEndpoint;
    public IPEndPoint? ClientEndpoint=>carrier.ClientEndpoint;
    public bool Exited=>Volatile.Read(ref disposed)!=0||carrier.Exited;
    public bool ControlsWirePackets=>carrier.ControlsWirePackets;
    public string FailureReason=>carrier.FailureReason;
    public string PeerCertificatePin=>carrier is IPairTransportIdentity identity?identity.PeerCertificatePin:carrier is StreamMeshTransport stream?stream.PeerCertificatePin:"";
    public StreamConnectionStatus? StreamConnection=>carrier is StreamMeshTransport stream?stream.ClientConnection:null;
    CoordinatedPairTransport(IMapping mapping,IMeshTransport carrier)
    {this.mapping=mapping;this.carrier=carrier;maintenance=mapping.Maintain(stop.Token);}
    public static async Task<CoordinatedPairTransport> Create(string components,string folder,MeshProfile mesh,IPEndPoint endpoint,Action<string> log,CancellationToken token,string[] servers,bool allowGatewayMapping=true)
    {
        if(!TransportModes.TcpAssistance(mesh.Pair.Mode))throw new IOException("此协议不使用 TCP 协调辅助");
        IMapping mapping=mesh.Pair.Mode=="faketcp"?await FakeTcpSourceMapping.Create(0,servers,log,token,allowGatewayMapping)
            :await MimicMapping.Create(0,log,token,servers,allowGatewayMapping:allowGatewayMapping,mode:mesh.Pair.Mode);
        IMeshTransport? carrier=null;
        try{
            carrier=mesh.Pair.Mode=="faketcp"?new FakeTcpAssistTransport(components,folder,mesh,endpoint,false,(FakeTcpSourceMapping)mapping)
                :TransportModes.Stream(mesh.Pair.Mode)?new StreamMeshTransport(mesh,endpoint,false,0,pairingBootstrap:true,sourceMapping:(ITcpSourceMapping)mapping,deferConnect:true)
                :new PacketCarrierTransport(components,folder,mesh,endpoint,false,0,"error",mapping:(MimicMapping)mapping,peerReflexive:OperatingSystem.IsWindows()&&mesh.Pair.Mode=="mimic");
            await ((IMeshPunchTransport)carrier).PreparePunch(endpoint,true,token);
            token.ThrowIfCancellationRequested();return new(mapping,carrier);
        }catch{carrier?.Dispose();await mapping.DisposeAsync();throw;}
    }
    public Task PreparePunch(IPEndPoint peer,bool client,CancellationToken token)=>((IMeshPunchTransport)carrier).PreparePunch(peer,client,token);
    public Task StartPunch(IPEndPoint peer,ReadOnlyMemory<byte> greeting,CancellationToken token)=>((IMeshPunchTransport)carrier).StartPunch(peer,greeting,token);
    public void Punch(IPEndPoint peer)=>((IMeshPunchTransport)carrier).Punch(peer);
    public void Punch(IPEndPoint peer,ReadOnlyMemory<byte> greeting)=>((IMeshPunchTransport)carrier).Punch(peer,greeting);
    public void Dispose()
    {
        if(Interlocked.Exchange(ref disposed,1)!=0)return;stop.Cancel();
        try{carrier.Dispose();}
        finally{try{mapping.DisposeAsync().AsTask().GetAwaiter().GetResult();}finally{try{maintenance.GetAwaiter().GetResult();}catch(OperationCanceledException){}finally{stop.Dispose();}}}
    }
}
