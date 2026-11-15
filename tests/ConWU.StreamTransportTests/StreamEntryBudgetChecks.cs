using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;

static class StreamEntryBudgetChecks
{
    public static async Task Run(Action<bool,string> check)
    {
        using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(12));var token=stop.Token;
        await using var reflector=new StreamMappingRecoveryChecks.Reflector(48080);
        var mesh=MeshIdentity.Create("","","tcp",direct:true);
        using var sink=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        using var application=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        using var reservation=new TcpListener(IPAddress.Loopback,0);reservation.Start();int port=((IPEndPoint)reservation.LocalEndpoint).Port;reservation.Stop();
        await using var listener=new StreamMeshTransport(mesh,(IPEndPoint)sink.Client.LocalEndPoint!,true,port);
        await using var client=new StreamMeshTransport(mesh,new(IPAddress.Loopback,port),false,0);
        async Task<bool> RoundTrip(){
            byte[] payload=RandomNumberGenerator.GetBytes(1280);await application.SendAsync(payload,client.ClientEndpoint!,token);
            var packet=await sink.ReceiveAsync(token);await sink.SendAsync(packet.Buffer,packet.RemoteEndPoint,token);
            return (await application.ReceiveAsync(token)).Buffer.SequenceEqual(payload);
        }
        check(await RoundTrip(),"business connection is active before gateway preparation");
        bool gatewayClosed=false;var stages=new List<EntryProbeProgress>();
        var options=new StreamMapping.Options(GatewayFactory:async (_,_,ct)=>{
            try{await Task.Delay(Timeout.Infinite,ct);throw new Exception("unreachable");}finally{gatewayClosed=true;}
        }){GatewayBudget=TimeSpan.FromMilliseconds(100),Progress=stages.Add};
        var clock=Stopwatch.StartNew();
        await using(var mapping=await StreamMapping.Create(port,_=>{},token,[reflector.Address],false,options)){
            check(gatewayClosed&&clock.Elapsed<TimeSpan.FromSeconds(3)&&mapping.IsValid,
                "slow gateway is canceled and joined before a bounded receiver-port STUN fallback succeeds");
            check(reflector.SourcePorts.All(p=>p==port)&&stages.Any(s=>s.Stage=="ReceiverStun")&&mapping.PublicEndpoint.Port==48080,
                "fallback reports its actual stage and keeps the listener's exact source port");
            check(!listener.Exited&&await RoundTrip(),"gateway timeout and STUN preparation preserve established business traffic");
        }
        check(!listener.Exited&&await RoundTrip(),"releasing the fallback observation does not close the independent listener or business session");
        int requests=reflector.Requests;
        using var canceled=new CancellationTokenSource(60);
        try{
            await StreamMapping.Create(port,_=>{},canceled.Token,[reflector.Address],false,
                options:new(GatewayFactory:async (_,_,ct)=>{await Task.Delay(Timeout.Infinite,ct);throw new Exception("unreachable");}){GatewayBudget=TimeSpan.FromSeconds(2)});
            throw new Exception("canceled gateway returned");
        }catch(OperationCanceledException){check(reflector.Requests==requests&&await RoundTrip(),"caller cancellation never starts fallback or interrupts a separate business connection");}
    }
}
