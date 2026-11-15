using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// Reuses UDP2RAW's existing authenticated prepared-start ABI and genuine
// FakeTCP+HTTP wire. This is not another protocol carrying FakeTCP's label.
public sealed class FakeTcpAssistTransport:IMeshTransport,IMeshPunchTransport
{
    readonly FakeTcpSourceMapping mapping;
    readonly string binary,folder;
    readonly IPEndPoint target;
    readonly bool listener,protocolClient;
    readonly SemaphoreSlim preparation=new(1,1);
    readonly CancellationTokenSource stop=new();
    NativeAttachment? native;
    TcpCaptureOwner? capture;
    Socket? bridge;
    Task bridgePump=Task.CompletedTask;
    CancellationTokenSource? bridgeStop;
    IPEndPoint? peer,wire;
    string configuration="";
    bool disposed;
    public IPEndPoint? ClientEndpoint{get;private set;}
    public bool ControlsWirePackets=>true;
    public bool Exited=>disposed;
    public string FailureReason=>"";
    public FakeTcpAssistTransport(string components,string folder,MeshProfile mesh,IPEndPoint target,bool server,FakeTcpSourceMapping mapping)
    {
        this.mapping=mapping;this.folder=folder;this.target=target;listener=server;protocolClient=!server||!mesh.IsOwner;
        binary=Path.Combine(components,"udp2raw-native"+(OperatingSystem.IsWindows()?".exe":""));
        if(!File.Exists(binary))throw new IOException("缺少 FakeTCP＋HTTP 同时打开原生组件");
        Directory.CreateDirectory(folder);
    }
    public async Task PreparePunch(IPEndPoint endpoint,bool client,CancellationToken token)
    {
        if(client!=protocolClient)throw new IOException("FakeTCP 协同的协议角色与本机网络角色不符");
        await preparation.WaitAsync(token);
        try{
            ObjectDisposedException.ThrowIf(disposed,this);
            // A new unhealthy-path cycle must own a fresh SO handshake even
            // when the peer rebooted behind the same public tuple. Duplicate
            // Prepare before Start can reuse an armed resource; a started
            // attachment cannot rewind its ISNs or its outer authentication.
            if(peer?.Equals(endpoint)==true&&native is {Exited:false,Armed:true,Started:false})return;
            await CloseNative();
            if(OperatingSystem.IsWindows()&&capture==null){
                capture=new(mapping.Lease,mapping.Generation,(local,helper)=>new WinDivertEndpointIo(Path.Combine(Path.GetDirectoryName(binary)!,"WinDivert.dll"),local,helper));
                await capture.Ready.WaitAsync(token);
            }
            IPEndPoint localUdp;
            using(var reserve=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp)){
                reserve.Bind(new IPEndPoint(IPAddress.Loopback,0));localUdp=(IPEndPoint)reserve.LocalEndPoint!;
            }
            string bind=client?localUdp.ToString():mapping.LocalEndpoint.ToString();
            string remote=client?endpoint.ToString():target.ToString();
            configuration=Path.Combine(folder,"assisted-faketcp-"+Guid.NewGuid().ToString("N")+".conf");
            string config=$"{(client?"-c":"-s")}\n-l {bind}\n-r {remote}\n-k {DirectPairWire.CarriageKey}\n--raw-mode faketcp\n--fix-gro\n--seq-mode 3\n--fake-http test.ustc.edu.cn\n--log-level 4\n";
            if(OperatingSystem.IsLinux())LinuxPlatform.PrivateWrite(configuration,System.Text.Encoding.UTF8.GetBytes(config));else await File.WriteAllTextAsync(configuration,config,token);
            try{
                native=await NativeAttachment.Launch(mapping.Lease,mapping.Generation,binary,["--conf-file",configuration],endpoint,!client,
                    Path.ChangeExtension(configuration,".log"),token,simultaneousOpen:true,startImmediately:false,captureOwner:capture);
                peer=endpoint;wire=client?localUdp:null;
                if(!listener)ClientEndpoint=localUdp;
                else if(client){
                    bridge=new(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);bridge.Bind(new IPEndPoint(IPAddress.Loopback,0));
                    bridgeStop=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);bridgePump=Pump(bridge,localUdp,bridgeStop.Token);
                }
            }catch{await CloseNative();throw;}
        }finally{preparation.Release();}
    }
    async Task Pump(Socket socket,IPEndPoint carrier,CancellationToken token)
    {
        byte[] bytes=new byte[2048];
        try{while(true){
            var incoming=await socket.ReceiveFromAsync(bytes,SocketFlags.None,new IPEndPoint(IPAddress.Loopback,0),token);
            IPEndPoint? destination=incoming.RemoteEndPoint.Equals(carrier)?target:incoming.RemoteEndPoint.Equals(target)?carrier:null;
            if(destination!=null)await socket.SendToAsync(bytes.AsMemory(0,incoming.ReceivedBytes),SocketFlags.None,destination,token);
        }}catch(Exception error)when(token.IsCancellationRequested&&error is OperationCanceledException or SocketException or ObjectDisposedException){}
    }
    public async Task StartPunch(IPEndPoint endpoint,ReadOnlyMemory<byte> greeting,CancellationToken token)
    {
        if(peer?.Equals(endpoint)!=true||native is not {Exited:false,Armed:true} active)throw new IOException("FakeTCP 本轮尚未完成原生资源准备");
        await active.Start(token);
        if(listener&&protocolClient&&!greeting.IsEmpty)await bridge!.SendToAsync(greeting,SocketFlags.None,wire!,token);
    }
    public void Punch(IPEndPoint endpoint)=>StartPunch(endpoint,ReadOnlyMemory<byte>.Empty,stop.Token).GetAwaiter().GetResult();
    public void Punch(IPEndPoint endpoint,ReadOnlyMemory<byte> greeting)=>StartPunch(endpoint,greeting,stop.Token).GetAwaiter().GetResult();
    async Task CloseNative()
    {
        bridgeStop?.Cancel();bridge?.Dispose();bridge=null;
        try{await bridgePump;}catch(OperationCanceledException){}finally{bridgeStop?.Dispose();bridgeStop=null;bridgePump=Task.CompletedTask;}
        if(native!=null){await native.DisposeAsync();native=null;}
        if(configuration.Length>0){File.Delete(configuration);configuration="";}
        peer=wire=null;ClientEndpoint=null;
    }
    public void Dispose()
    {
        if(disposed)return;disposed=true;stop.Cancel();preparation.Wait();
        try{CloseNative().GetAwaiter().GetResult();if(capture!=null){capture.DisposeAsync().AsTask().GetAwaiter().GetResult();capture=null;}}
        finally{preparation.Release();preparation.Dispose();stop.Dispose();}
    }
}
