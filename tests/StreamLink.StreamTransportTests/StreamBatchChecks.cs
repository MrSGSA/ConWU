using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using StreamLink.Core;

static class StreamBatchChecks
{
    public static async Task Run(Action<bool,string> check)
    {
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate=StreamCertificates.CreateServer(key,DateTimeOffset.UtcNow.AddDays(1));
        var profile=MeshIdentity.Create("","","https",direct:true);
        profile.Pair=profile.Pair with{TransportKeyPin=StreamMeshTransport.CertificatePin(certificate)};
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        foreach (bool serverBatch in new[]{false,true}) {
            using var sink=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
            int port=FreePort();
            await using var listener=new StreamMeshTransport(profile,(IPEndPoint)sink.Client.LocalEndPoint!,true,port,()=>certificate,batchDatagrams:serverBatch);
            using var sender=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
            await using var client=new StreamMeshTransport(profile,new(IPAddress.Loopback,port),false,0);
            var payload=RandomNumberGenerator.GetBytes(1280);
            await sender.SendAsync(payload,client.ClientEndpoint!,deadline.Token);
            var packet=await sink.ReceiveAsync(deadline.Token);
            check(packet.Buffer.SequenceEqual(payload)&&client.BatchingEnabled==serverBatch,
                serverBatch?"new HTTPS peers negotiate bounded length-prefixed batches":"new HTTPS clients retain single-datagram compatibility with an older listener");
            await sink.SendAsync(payload,packet.RemoteEndPoint,deadline.Token);
            check((await sender.ReceiveAsync(deadline.Token)).Buffer.SequenceEqual(payload),"negotiated and legacy HTTPS framing both preserve return datagrams");
        }
        using(var sink=new UdpClient(new IPEndPoint(IPAddress.Loopback,0))) {
            int port=FreePort();
            await using var listener=new StreamMeshTransport(profile,(IPEndPoint)sink.Client.LocalEndPoint!,true,port,()=>certificate);
            using var socket=new ClientWebSocket();
            socket.Options.Proxy=null;socket.Options.AddSubProtocol("conwu.stream.v1");
            socket.Options.SetRequestHeader("X-ConWU-Datagram-Batch","1");
            socket.Options.RemoteCertificateValidationCallback=(_,cert,_,_)=>cert?.GetCertHashString()==certificate.GetCertHashString();
            await socket.ConnectAsync(new($"wss://127.0.0.1:{port}/conwu/stream"),deadline.Token);
            byte[] first=RandomNumberGenerator.GetBytes(1280),second=RandomNumberGenerator.GetBytes(2048);
            byte[] batch=new byte[first.Length+second.Length+4];
            BinaryPrimitives.WriteUInt16BigEndian(batch,(ushort)first.Length);first.CopyTo(batch,2);
            BinaryPrimitives.WriteUInt16BigEndian(batch.AsSpan(first.Length+2),(ushort)second.Length);second.CopyTo(batch,first.Length+4);
            await socket.SendAsync(batch.AsMemory(0,3),WebSocketMessageType.Binary,false,deadline.Token);
            await socket.SendAsync(batch.AsMemory(3),WebSocketMessageType.Binary,true,deadline.Token);
            var one=await sink.ReceiveAsync(deadline.Token);var two=await sink.ReceiveAsync(deadline.Token);
            check(one.Buffer.SequenceEqual(first)&&two.Buffer.SequenceEqual(second),"fragmented HTTPS batches preserve order and individual datagram boundaries");
            byte[] malformed=new byte[first.Length+5];
            BinaryPrimitives.WriteUInt16BigEndian(malformed,(ushort)first.Length);first.CopyTo(malformed,2);
            BinaryPrimitives.WriteUInt16BigEndian(malformed.AsSpan(first.Length+2),100);
            await socket.SendAsync(malformed,WebSocketMessageType.Binary,true,deadline.Token);
            bool closed=false;
            try { await socket.ReceiveAsync(new byte[1],deadline.Token); }
            catch(WebSocketException) { closed=true; }
            using var quiet=new CancellationTokenSource(150);
            bool discarded=false;
            try { await sink.ReceiveAsync(quiet.Token); }
            catch(OperationCanceledException) { discarded=true; }
            check(closed&&discarded&&!listener.Exited,"an invalid trailing batch frame cannot deliver an earlier prefix or stop the listener");
        }
        using(var sink=new UdpClient(new IPEndPoint(IPAddress.Loopback,0))) {
            int port=FreePort();var tcp=MeshIdentity.Create("","","tcp",direct:true);
            await using var listener=new StreamMeshTransport(tcp,(IPEndPoint)sink.Client.LocalEndPoint!,true,port);
            using var socket=new TcpClient();await socket.ConnectAsync(IPAddress.Loopback,port,deadline.Token);
            var stream=socket.GetStream();byte[] frames=[0,1,42,0,2,43,44];
            await stream.WriteAsync(frames.AsMemory(0,1),deadline.Token);
            await Task.Delay(10,deadline.Token);
            await stream.WriteAsync(frames.AsMemory(1,4),deadline.Token);
            await Task.Delay(10,deadline.Token);
            await stream.WriteAsync(frames.AsMemory(5),deadline.Token);
            var one=await sink.ReceiveAsync(deadline.Token);var two=await sink.ReceiveAsync(deadline.Token);
            check(one.Buffer.SequenceEqual(new byte[]{42})&&two.Buffer.SequenceEqual(new byte[]{43,44}),"buffered TCP parsing handles a split header and several coalesced frames");
        }
    }
    static int FreePort()
    {
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();
        int port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();return port;
    }
}
