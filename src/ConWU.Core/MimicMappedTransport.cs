using System.Net;

namespace StreamLink.Core;

public interface IMappedMeshTransport:IMeshTransport { IPEndPoint PublicEndpoint{get;} }

// The pairing client owns its temporary source port, native process, gateway
// lease and keepalive together. Stopping it does not change any saved network.
public sealed class MimicMappedTransport:IMappedMeshTransport
{
    readonly MimicMapping mapping;
    readonly PacketCarrierTransport carrier;
    readonly CancellationTokenSource stop=new();
    readonly Task maintenance;
    int disposed;
    public IPEndPoint PublicEndpoint=>mapping.PublicEndpoint;
    public IPEndPoint? ClientEndpoint=>carrier.ClientEndpoint;
    public bool Exited=>Volatile.Read(ref disposed)!=0||carrier.Exited||maintenance.IsCompleted;
    public bool ControlsWirePackets=>true;
    public string FailureReason=>carrier.FailureReason;
    MimicMappedTransport(MimicMapping mapping,PacketCarrierTransport carrier)
    {this.mapping=mapping;this.carrier=carrier;maintenance=mapping.Maintain(stop.Token);}
    public static async Task<MimicMappedTransport> Create(string components,string folder,MeshProfile temporary,IPEndPoint endpoint,Action<string> log,CancellationToken token,string[]? servers=null,bool allowGatewayMapping=true)
    {
        var mapping=await MimicMapping.Create(0,log,token,servers,allowGatewayMapping:allowGatewayMapping);PacketCarrierTransport? carrier=null;
        try{
            carrier=new(components,folder,temporary,endpoint,false,0,"error",mapping:mapping,peerReflexive:true);
            token.ThrowIfCancellationRequested();return new(mapping,carrier);
        }catch{carrier?.Dispose();await mapping.DisposeAsync();throw;}
    }
    public void Dispose()
    {
        if(Interlocked.Exchange(ref disposed,1)!=0)return;
        stop.Cancel();
        try{carrier.Dispose();}
        finally{
            try{mapping.DisposeAsync().AsTask().GetAwaiter().GetResult();}
            finally{try{maintenance.GetAwaiter().GetResult();}catch(OperationCanceledException){}finally{stop.Dispose();}}
        }
    }
}
