using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    // Real production native processes and control channels, with only their
    // raw IPv4 I/O replaced by the explicit parser-test loopback carrier.
    sealed class PairWorkspaceNativeWire:IAsyncDisposable
    {
        readonly UdpClient socket=new(new IPEndPoint(IPAddress.Loopback,0));
        readonly CancellationTokenSource stop=new();
        readonly Dictionary<int,IPEndPoint> routes=[];
        readonly HashSet<int> listeners=[];
        readonly string components,folder;
        readonly Task pump;
        public int[] Ports {get;}=new int[3];
        public bool SawHttp;
        public int FromClients,FromServers;
        public PairWorkspaceNativeWire(string binary,string folder)
        {
            this.folder=folder;Directory.CreateDirectory(folder);
            components=Path.Combine(folder,"components");Directory.CreateDirectory(components);
            File.Copy(binary,Path.Combine(components,"udp2raw-native.exe"),true);
            var reservations=new List<Socket>();
            try{for(int i=0;i<Ports.Length;i++){
                var reservation=ReserveNativeListener("faketcp");reservations.Add(reservation);
                Ports[i]=((IPEndPoint)reservation.LocalEndPoint!).Port;listeners.Add(Ports[i]);
            }}finally{foreach(var reservation in reservations)reservation.Dispose();}
            pump=Run();
        }
        public IMeshTransport Transport(MeshTransportRequest request)
        {
            using var reservation=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
            int wirePort=((IPEndPoint)reservation.Client.LocalEndPoint!).Port;
            if(request.Server)lock(routes)routes[request.Port]=new(IPAddress.Loopback,wirePort);
            var environment=new Dictionary<string,string>{["STREAMLINK_TEST_BIND"]=wirePort.ToString(),["STREAMLINK_TEST_PEER"]=((IPEndPoint)socket.Client.LocalEndPoint!).Port.ToString()};
            reservation.Dispose();
            return new MeshTransport(components,folder,request.Mesh,request.Target,request.Server,request.Port,null,"info",environment,request.ReserveEndpoint,request.Egress);
        }
        async Task Run()
        {
            try{while(!stop.IsCancellationRequested){
                UdpReceiveResult received;
                try{received=await socket.ReceiveAsync(stop.Token);}
                catch(SocketException ex)when(ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused){continue;}
                var bytes=received.Buffer;
                if(bytes.Length<40)continue;int header=(bytes[0]&15)*4;
                if(header<20||bytes.Length<header+20||bytes[9]!=6)continue;
                int source=BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(header)),destination=BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(header+2));
                IPEndPoint? target;lock(routes){routes[source]=received.RemoteEndPoint;target=routes.GetValueOrDefault(destination);}
                if(listeners.Contains(source))Interlocked.Increment(ref FromServers);else Interlocked.Increment(ref FromClients);
                if(bytes.AsSpan().IndexOf("Host: test.ustc.edu.cn"u8)>=0)SawHttp=true;
                if(target!=null)await socket.SendAsync(bytes,target,stop.Token);
            }}catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        }
        public async ValueTask DisposeAsync(){stop.Cancel();try{await pump;}finally{socket.Dispose();stop.Dispose();}}
    }
}
