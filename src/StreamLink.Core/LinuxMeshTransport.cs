using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace StreamLink.Core;

public sealed class LinuxMeshTransport : IMeshTransport
{
    [DllImport("libc",SetLastError=true)]static extern int kill(int pid,int signal);
    readonly string configuration;
    LinuxKernelResource? resource;Socket? sourceLease;
    Process? process;Task? output,error;int disposed;
    public IPEndPoint? ClientEndpoint {get;}
    public bool Exited=>process?.HasExited!=false;
    public bool ControlsWirePackets=>true;
    public string FailureReason=>Exited?"Linux 原生传输已退出，请查看本机会话日志":"";
    public LinuxMeshTransport(string components,string sessionRoot,MeshProfile profile,IPEndPoint target,bool server,int listenPort,IMapping? mapping,string logLevel,Action<IPEndPoint>? reserve=null) {
        if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException();
        configuration=Path.Combine(sessionRoot,"raw-"+Guid.NewGuid().ToString("N")+".conf");
        string binary=Path.Combine(components,"udp2raw-native");
        string binding;
        if(server)binding=$"{mapping?.LocalAddress??IPAddress.Any}:{listenPort}";
        else {using var port=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);port.Bind(new IPEndPoint(IPAddress.Loopback,0));ClientEndpoint=(IPEndPoint)port.LocalEndPoint!;binding=ClientEndpoint.ToString();reserve?.Invoke(ClientEndpoint);}
        var ticket=new Invitation(1,profile.Pair.Network,profile.Pair.Secret,target.ToString(),profile.Pair.Mode,"test.ustc.edu.cn",DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds());
        string secret=profile.Pair.DirectBootstrap?DirectPairWire.CarriageKey:ticket.RawKey;
        try {
            string[]? listenerRule=null;
            string sourceOptions="";
            if(profile.Pair.Mode=="faketcp") {
                resource=new();string table=resource.Table;
                LinuxPlatform.Run("nft","add","table","inet",table);
                LinuxPlatform.Run("nft","add","chain","inet",table,"input","{","type","filter","hook","input","priority","-150",";","policy","accept",";","}");
                var rule=new List<string>{"add","rule","inet",table,"input"};
                if(server){if(mapping?.LocalAddress is {} local)rule.AddRange(["ip","daddr",local.ToString()]);rule.AddRange(["tcp","dport",listenPort.ToString(),"drop"]);}
                else {
                    using var route=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);route.Connect(target);
                    var local=((IPEndPoint)route.LocalEndPoint!).Address;
                    sourceLease=new(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp){ExclusiveAddressUse=true};sourceLease.Bind(new IPEndPoint(local,0));
                    var source=(IPEndPoint)sourceLease.LocalEndPoint!;
                    sourceOptions=$"--source-ip {local}\n--source-port {source.Port}\n";
                    rule.AddRange(["ip","saddr",target.Address.ToString(),"ip","daddr",local.ToString(),"tcp","sport",target.Port.ToString(),"tcp","dport",source.Port.ToString(),"drop"]);
                }
                if(server)listenerRule=rule.ToArray();else LinuxPlatform.Run("nft",rule.ToArray());
            }
            string config=$"{(server?"-s":"-c")}\n-l {binding}\n-r {target}\n-k {secret}\n--raw-mode {profile.Pair.Mode}\n--fix-gro\n--seq-mode 3\n--log-level {(logLevel=="debug"?5:logLevel=="off"?0:4)}\n--disable-color\n";
            if(profile.Pair.Mode=="faketcp")config+="--fake-http test.ustc.edu.cn\n";
            config+=sourceOptions;
            LinuxPlatform.PrivateWrite(configuration,System.Text.Encoding.UTF8.GetBytes(config));
            var start=new ProcessStartInfo(binary){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
            start.ArgumentList.Add("--conf-file");start.ArgumentList.Add(configuration);
            foreach(var name in start.Environment.Keys.Where(k=>k.StartsWith("STREAMLINK_")).ToArray())start.Environment.Remove(name);
            if(profile.Pair.DirectBootstrap)start.Environment["STREAMLINK_DIRECT_RENDEZVOUS"]="1";
            if(server&&mapping is UdpMapping)start.Environment["STREAMLINK_UDP_SHARED_BIND"]="1";
            process=Process.Start(start)??throw new IOException("Linux 原生传输启动失败");
            var log=new StreamWriter(Path.ChangeExtension(configuration,".log")){AutoFlush=true};
            var gate=new SemaphoreSlim(1,1);int finished=0;
            var ready=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            async Task Drain(StreamReader reader){try{while(await reader.ReadLineAsync() is {} line){if(line=="STREAMLINK_LISTENER_READY"){ready.TrySetResult();continue;}await gate.WaitAsync();try{if(logLevel!="off")await log.WriteLineAsync(line.Replace(secret,"[redacted]"));}catch(IOException){}finally{gate.Release();}}}finally{if(Interlocked.Increment(ref finished)==2)await log.DisposeAsync();}}
            output=Drain(process.StandardOutput);error=Drain(process.StandardError);
            if(listenerRule!=null){
                Task.WhenAny(ready.Task,process.WaitForExitAsync()).WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
                if(!ready.Task.IsCompleted||process.HasExited)throw new IOException("本机接收端口未能独占绑定；请检查端口占用或原生传输日志");
                LinuxPlatform.Run("nft",listenerRule);
            }
        }catch{Dispose();throw;}
    }
    public void Dispose() {
        if(Interlocked.Exchange(ref disposed,1)!=0)return;
        try {
            if(process!=null)try{if(!process.HasExited){kill(process.Id,15);if(!process.WaitForExit(3000)){process.Kill();process.WaitForExit();}}Task.WhenAll(new[]{output,error}.OfType<Task>()).GetAwaiter().GetResult();}finally{process.Dispose();}
        }finally {
            try{resource?.Dispose();}finally{sourceLease?.Dispose();File.Delete(configuration);}
        }
    }
}
