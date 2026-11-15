using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Authentication;

namespace StreamLink.Core;

public sealed partial class StreamMeshTransport
{
    public Task PreparePunch(IPEndPoint peer,bool client,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if(sourceMapping==null||client!=protocolClient||peer.AddressFamily!=AddressFamily.InterNetwork||peer.Port==0)
            throw new IOException("TCP 同端口探测资源或协议角色不符");
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed)!=0,this);
        return Task.CompletedTask;
    }
    public Task StartPunch(IPEndPoint peer,ReadOnlyMemory<byte> greeting,CancellationToken token)
    {
        _=PreparePunch(peer,protocolClient,token);
        if(greeting.Length>128)throw new ArgumentException("协同探测问候过长");
        if(!greeting.IsEmpty)punchGreetings[peer]=greeting.ToArray();
        // A failed active open must not close the passive listener or another
        // established association. Both use the reflected source port.
        lock(punchConnections){
            if(punchConnections.TryGetValue(peer,out var prior)&&!prior.IsCompleted)return Task.CompletedTask;
            var pending=PunchConnection(peer,stop.Token);punchConnections[peer]=pending;
        }
        return Task.CompletedTask;
    }
    public void Punch(IPEndPoint peer)=>StartPunch(peer,ReadOnlyMemory<byte>.Empty,stop.Token).GetAwaiter().GetResult();
    public void Punch(IPEndPoint peer,ReadOnlyMemory<byte> greeting)=>StartPunch(peer,greeting,stop.Token).GetAwaiter().GetResult();
    async Task PunchConnection(IPEndPoint peer,CancellationToken token)
    {
        using var linked=CancellationTokenSource.CreateLinkedTokenSource(stop.Token,token);
        using var tcp=new TcpClient(AddressFamily.InterNetwork){NoDelay=true};
        var id=Guid.NewGuid();clients[id]=tcp;
        try{
            tcp.Client.ExclusiveAddressUse=false;
            tcp.Client.SetSocketOption(SocketOptionLevel.Socket,SocketOptionName.ReuseAddress,true);
            tcp.Client.Bind(sourceMapping!.LocalEndpoint);
            ClientPhase("TcpConnecting");
            using(var deadline=CancellationTokenSource.CreateLinkedTokenSource(linked.Token)){
                deadline.CancelAfter(8000);await tcp.ConnectAsync(peer.Address,peer.Port,deadline.Token);
            }
            ClientPhase("TcpConnected");
            using var udp=bridgeServer?LocalSocket():null;
            await Bridge(tcp,bridgeServer?udp:local,bridgeServer?bridgeTarget:null,serverCertificate,
                protocolClient?(peer,mesh.Pair.TransportKeyPin??""):null,bootstrap,
                greeting:punchGreetings.GetValueOrDefault(peer));
        }catch(Exception error)when(error is IOException or SocketException or OperationCanceledException or AuthenticationException or WebSocketException or ObjectDisposedException){
            if(!stop.IsCancellationRequested)Volatile.Write(ref lastConnectionFailure,FailureDetails(error));
        }finally{clients.TryRemove(id,out _);}
    }
}
