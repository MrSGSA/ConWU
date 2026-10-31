using System.Buffers.Binary;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;

static class NativeControlFailureTests
{
    internal static async Task<object> Run(string binary,string folder,Action<bool,string> check,CancellationToken token)
    {
        var outcomes=new List<object>();
        foreach(string failure in new[]{"timeout","bad-reply","broken-pipe"}){
            string name="StreamLink.Legacy."+Guid.NewGuid().ToString("N"),log=Path.Combine(folder,"native-control-"+failure+".log");
            byte[] secret=RandomNumberGenerator.GetBytes(64);string hex=Convert.ToHexString(secret);
            using var pipe=new NamedPipeServerStream(name,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);
            using var receiver=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
            using var carrier=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));int io=((IPEndPoint)carrier.Client.LocalEndPoint!).Port;carrier.Dispose();
            using var binding=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));int localPort=((IPEndPoint)binding.Client.LocalEndPoint!).Port;binding.Dispose();
            var environment=new Dictionary<string,string>{["STREAMLINK_LEGACY_CONTROL"]=name,["STREAMLINK_LEGACY_AUTH"]=hex,
                ["STREAMLINK_LEGACY_PARENT"]=Environment.ProcessId.ToString(),["STREAMLINK_TEST_BIND"]=io.ToString(),
                ["STREAMLINK_TEST_PEER"]=((IPEndPoint)receiver.Client.LocalEndPoint!).Port.ToString()};
            using var job=new ChildJob();
            var child=job.Start(binary,["-c","-l","127.0.0.1:"+localPort,"-r","127.0.0.1:"+NativeTestPorts.Take(),"-k","failure-fixture",
                "--raw-mode","faketcp","--fake-http","test.ustc.edu.cn","--log-level","4"],log,environment,[hex]);
            await pipe.WaitForConnectionAsync(token).WaitAsync(TimeSpan.FromSeconds(5),token);
            var hello=new byte[64];await pipe.ReadExactlyAsync(hello,token);
            check(CryptographicOperations.FixedTimeEquals(secret,hello),failure+": actual native child authenticates before fault injection");
            await pipe.WriteAsync(secret,token);
            // udp2raw starts the handshake on its first local datagram. Retry
            // only this fixture trigger until the child has bound that socket.
            var frame=new byte[56];var request=pipe.ReadExactlyAsync(frame,token).AsTask();
            for(int i=0;!request.IsCompleted&&i<40;i++){
                await receiver.SendAsync(new byte[64],new IPEndPoint(IPAddress.Loopback,localPort),token);await Task.Delay(50,token);
            }
            await request.WaitAsync(TimeSpan.FromSeconds(3),token);
            if(failure=="bad-reply"){
                var reply=new byte[16];BinaryPrimitives.WriteUInt64LittleEndian(reply,BinaryPrimitives.ReadUInt64LittleEndian(frame)+1);await pipe.WriteAsync(reply,token);
            }else if(failure=="broken-pipe")pipe.Dispose();
            await child.WaitForExitAsync(token).WaitAsync(TimeSpan.FromSeconds(5),token);
            int exitCode=child.ExitCode;
            child.WaitForExit(); // drains redirected logs before assertions
            using var stream=new FileStream(log,FileMode.Open,FileAccess.Read,FileShare.ReadWrite);using var reader=new StreamReader(stream);
            string text=await reader.ReadToEndAsync(token);
            string expected=failure=="bad-reply"?"stage=ReplyValidation":failure=="timeout"?"stage=ReplyRead reason=Timeout":"stage=ReplyRead reason=IoError";
            check(exitCode!=0&&text.Contains(expected)&&text.Contains("legacy control owner lost"),failure+": native fail-closed exit retains its precise cause");
            check(!text.Contains(hex),failure+": fault diagnostics contain no attachment secret");
            outcomes.Add(new{failure,expected,exitCode});
        }
        return new{outcomes,scope="actual native loopback backend and Windows IPC; no physical driver"};
    }
}
