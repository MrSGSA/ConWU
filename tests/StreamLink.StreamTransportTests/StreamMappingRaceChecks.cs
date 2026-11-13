using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using StreamLink.Core;

static class StreamMappingRaceChecks
{
    public static async Task Run(Action<bool,string> check)
    {
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var token=deadline.Token;
        var samples=new List<(int Parallelism,double Ms)>();
        foreach(int parallelism in new[]{1,2,2,1,1,2}){
            await using var slow=new StreamMappingRecoveryChecks.Reflector(48010){Mode=2};
            await using var fast=new StreamMappingRecoveryChecks.Reflector(48011);
            var listener=new TcpListener(IPAddress.Loopback,0);
            listener.Server.ExclusiveAddressUse=false;
            listener.Server.SetSocketOption(SocketOptionLevel.Socket,SocketOptionName.ReuseAddress,true);
            listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;
            try{
                var clock=Stopwatch.StartNew();
                await using(var mapping=await StreamMapping.Create(port,_=>{},token,[slow.Address,fast.Address],false,options:new(false,InitialParallelism:parallelism))){
                    samples.Add((parallelism,clock.Elapsed.TotalMilliseconds));
                    check(mapping.IsValid&&((StreamMapping)mapping).StunServer==fast.Address&&mapping.PublicEndpoint.Port==48011,
                        $"TCP discovery concurrency {parallelism}: unresponsive first reflector cannot mask a valid configured candidate");
                    await Until(()=>Volatile.Read(ref slow.Active)==0,token);
                    check(Volatile.Read(ref fast.Active)==1&&fast.Requests>=2&&slow.SourcePorts.Concat(fast.SourcePorts).All(p=>p==port),
                        $"TCP discovery concurrency {parallelism}: losing flow closes, winning flow is rechecked, exact receiver port is retained");
                    using var client=new TcpClient();await client.ConnectAsync(IPAddress.Loopback,port,token);
                    using var accepted=await listener.AcceptTcpClientAsync(token);
                    check(client.Connected&&accepted.Connected,"STUN candidate race leaves the existing TCP listener available");
                }
                await Until(()=>Volatile.Read(ref fast.Active)==0,token);
            }finally{listener.Stop();}
        }
        double Median(int p){var values=samples.Where(s=>s.Parallelism==p).Select(s=>s.Ms).Order().ToArray();return values[values.Length/2];}
        double sequential=Median(1),raced=Median(2);
        check(raced<sequential*.6,"bounded same-port speculation reduces a blackholed first reflector's discovery delay in alternating controls");
        Console.WriteLine(JsonSerializer.Serialize(new{scope="real kernel TCP listener and STUN sockets on loopback; no NAT/ISP claim",sequentialMedianMs=sequential,racedMedianMs=raced,
            samples=samples.Select(s=>new{parallelism=s.Parallelism,ms=s.Ms})}));

        await using(var healthy=new StreamMappingRecoveryChecks.Reflector(48012))
        await using(var unused=new StreamMappingRecoveryChecks.Reflector(48013)){
            int port=FreePort();
            await using var mapping=await StreamMapping.Create(port,_=>{},token,[healthy.Address,unused.Address],false,options:new(false));
            check(((StreamMapping)mapping).StunServer==healthy.Address&&healthy.SourcePorts.Count==1&&unused.SourcePorts.Count==0,
                "a promptly responding preferred reflector does not open an unnecessary speculative flow");
        }
        await using(var a=new StreamMappingRecoveryChecks.Reflector(48014){Mode=2})
        await using(var b=new StreamMappingRecoveryChecks.Reflector(48015){Mode=2})
        await using(var c=new StreamMappingRecoveryChecks.Reflector(48016){Mode=2})
        await using(var d=new StreamMappingRecoveryChecks.Reflector(48017){Mode=2}){
            var reflectors=new[]{a,b,c,d};
            using var cancel=CancellationTokenSource.CreateLinkedTokenSource(token);cancel.CancelAfter(650);
            bool cancelled=false;
            try{await StreamMapping.Create(FreePort(),_=>{},cancel.Token,reflectors.Select(r=>r.Address).ToArray(),false,options:new(false));}
            catch(OperationCanceledException)when(cancel.IsCancellationRequested){cancelled=true;}
            await Until(()=>reflectors.All(r=>Volatile.Read(ref r.Active)==0),token);
            check(cancelled&&a.SourcePorts.Count==1&&reflectors.Sum(r=>r.SourcePorts.Count)==2,"four configured blocked reflectors open at most two flows; cancellation joins and closes both");
        }
        await using(var unstable=new StreamMappingRecoveryChecks.Reflector(48018){Mode=4})
        await using(var valid=new StreamMappingRecoveryChecks.Reflector(48019)){
            await using var mapping=await StreamMapping.Create(FreePort(),_=>{},token,[unstable.Address,valid.Address],false,options:new(false));
            await Until(()=>Volatile.Read(ref unstable.Active)==0,token);
            check(((StreamMapping)mapping).StunServer==valid.Address&&mapping.PublicEndpoint.Port==48019&&valid.Requests>=2,
                "a first-response winner that fails its follow-up transaction is retired before another candidate is selected");
        }
    }
    static int FreePort(){var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();return port;}
    static async Task Until(Func<bool> ready,CancellationToken token){using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(2500);while(!ready())await Task.Delay(10,deadline.Token);}
}
