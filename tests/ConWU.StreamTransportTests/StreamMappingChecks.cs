using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using StreamLink.Core;

static class StreamMappingChecks
{
    public static async Task Run(Action<bool,string> check)
    {
        using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var reflector=new TcpListener(IPAddress.Loopback,0);reflector.Start();
        int reflectedPort=48000,observedPort=0;bool withhold=false;int queries=0;
        var serving=Task.Run(async()=>{
            try{while(!stop.IsCancellationRequested){
                using var client=await reflector.AcceptTcpClientAsync(stop.Token);
                observedPort=((IPEndPoint)client.Client.RemoteEndPoint!).Port;
                try{while(!stop.IsCancellationRequested){
                    byte[] request=new byte[20];await client.GetStream().ReadExactlyAsync(request,stop.Token);Interlocked.Increment(ref queries);
                    if(withhold){await Task.Delay(Timeout.Infinite,stop.Token);break;}
                    byte[] response=new byte[32];request.CopyTo(response,0);response[0]=1;response[1]=1;response[3]=12;
                    BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(20),0x20);response[23]=8;response[25]=1;
                    BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(26),(ushort)(Volatile.Read(ref reflectedPort)^0x2112));
                    byte[] ip=[203,0,113,20];for(int n=0;n<4;n++)response[28+n]=(byte)(ip[n]^request[4+n]);
                    await client.GetStream().WriteAsync(response,stop.Token);
                }}catch(Exception e)when(e is IOException or SocketException){}
            }}catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        });
        int port=FreePort();var owner=MeshIdentity.Create("","","tcp",direct:true);
        using var sink=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        try{
            await using(var listener=new StreamMeshTransport(owner,(IPEndPoint)sink.Client.LocalEndPoint!,true,port)){
                var mapping=await StreamMapping.Create(port,_=>{},stop.Token,[reflector.LocalEndpoint.ToString()!],false,options:new(false,TimeSpan.FromMilliseconds(75)));
                check(mapping.IsValid&&observedPort==port&&queries>=2,"real TCP STUN binds the receiver's exact port while its listener is active");
                check(mapping.PublicEndpoint.Equals(new IPEndPoint(IPAddress.Parse("203.0.113.20"),48000)),"TCP STUN candidate is parsed from an actual framed response");
                var changed=new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);mapping.Changed+=ep=>changed.TrySetResult(ep);
                Volatile.Write(ref reflectedPort,48001);var work=mapping.Maintain(stop.Token);
                check((await changed.Task.WaitAsync(TimeSpan.FromSeconds(2))).Port==48001,"retained TCP STUN flow publishes changed endpoints during maintenance");
                await mapping.DisposeAsync();try{await work;}catch(OperationCanceledException){}
                check(!mapping.IsValid&&!listener.Exited,"releasing a TCP STUN mapping keeps its shared listener alive");
                using var inbound=new TcpClient();await inbound.ConnectAsync(IPAddress.Loopback,port,stop.Token);
                check(inbound.Connected,"the kernel TCP listener still accepts connections after mapping release");
                withhold=true;
                using var canceled=new CancellationTokenSource(250);bool wasCanceled=false;
                try{await StreamMapping.Create(port,_=>{},canceled.Token,[reflector.LocalEndpoint.ToString()!],false,options:new(false));}catch(OperationCanceledException){wasCanceled=true;}
                check(wasCanceled&&!listener.Exited,"canceling an incomplete TCP STUN query releases only its own outbound socket");
            }
            var reused=new TcpListener(IPAddress.Loopback,port);reused.Start();reused.Stop();check(true,"TCP mapping and listener together release their exact port");
        }finally{stop.Cancel();reflector.Stop();await serving;}
    }
    static int FreePort(){var value=new TcpListener(IPAddress.Loopback,0);value.Start();int port=((IPEndPoint)value.LocalEndpoint).Port;value.Stop();return port;}
}
