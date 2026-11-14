using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using StreamLink.Core;

static class NativeChecks
{
    public static Task Run(string components,string mode="phantun")
    {
        string root=Path.Combine(Path.GetTempPath(),"conwu-phantun-native-"+Guid.NewGuid().ToString("N"));
        string? previous=Environment.GetEnvironmentVariable("STREAMLINK_PROFILE_ROOT");
        Directory.CreateDirectory(root);Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",root);
        try{
            using var target=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);target.Bind(new IPEndPoint(IPAddress.Loopback,0));
            int port;using(var reserve=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp)){reserve.Bind(new IPEndPoint(IPAddress.Any,0));port=((IPEndPoint)reserve.LocalEndPoint!).Port;}
            var profile=MeshIdentity.Create("","",mode,direct:true,pairwise:true);
            using(var listener=new PacketCarrierTransport(components,root,profile,(IPEndPoint)target.LocalEndPoint!,true,port,"info")){
                if(listener.Exited||listener.ProcessId<=0)throw new IOException("native listener not ready");
                try{using var collision=new PacketCarrierTransport(components,root,profile,(IPEndPoint)target.LocalEndPoint!,true,port,"info");throw new IOException("duplicate source port was accepted");}
                catch(Exception error)when(error is SocketException or IOException&&!error.Message.Contains("duplicate source port was accepted")){}
                if(listener.Exited)throw new IOException("collision disturbed the original listener");
            }
            using(var released=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp)){released.ExclusiveAddressUse=true;released.Bind(new IPEndPoint(IPAddress.Any,port));}
            using(var bootstrap=new PacketCarrierTransport(components,root,profile,new(IPAddress.Parse("192.0.2.1"),49197),false,0,"info")){
                if(bootstrap.Exited||bootstrap.ClientEndpoint is not {Port:>0})throw new IOException("bootstrap must allocate its client ports instead of requiring a listener");
            }
            Console.WriteLine(JsonSerializer.Serialize(new{status="Pass",checks=new[]{"native ABI and dependency preflight","packet capture readiness","duplicate port rejection without disturbing owner","graceful component stop","port released","pre-enrollment client owns dynamic ports without a listener"}}));
            return Task.CompletedTask;
        }finally{Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",previous);if(Directory.Exists(root))Directory.Delete(root,true);}
    }
}
