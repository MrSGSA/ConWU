using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task EntryConnectionReuse()
    {
        var builder=WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options=>options.Listen(IPAddress.Loopback,0));
        await using var server=builder.Build();
        int reads=0,connections=0;
        server.MapGet("/entry",async context=>{
            int current=Interlocked.Increment(ref reads);
            context.Response.Headers.CacheControl="no-store";
            await context.Response.WriteAsync($"streamlink=203.0.113.8:{45000+current}\n");
        });
        server.MapGet("/large-error",async context=>{
            context.Response.StatusCode=503;context.Response.ContentType="application/json";
            await context.Response.StartAsync();
            await context.Response.WriteAsync("{\"error\":\"entry report expired\",\"debug\":\"token=must-not-leak"+new string('x',2048)+"\"}");
        });
        server.MapGet("/stalled-error",async context=>{
            context.Response.StatusCode=503;context.Response.ContentType="application/json";
            await context.Response.StartAsync();
            await context.Response.WriteAsync("{");await context.Response.Body.FlushAsync();
            try {await Task.Delay(Timeout.Infinite,context.RequestAborted);}catch(OperationCanceledException)when(context.RequestAborted.IsCancellationRequested){}
        });
        await server.StartAsync();
        int port=new Uri(server.Urls.Single()).Port;
        Task<IPAddress[]> Public(string _,CancellationToken token)=>Task.FromResult(new[]{IPAddress.Parse("203.0.113.2")});
        Task<string[]> Empty(string _,CancellationToken token)=>Task.FromResult(Array.Empty<string>());
        async Task<Stream> Connect(IPEndPoint endpoint,CancellationToken token){
            Check(endpoint.Address.Equals(IPAddress.Parse("203.0.113.2")),"reused HTTP requests retain DNS validation and pinned public destinations");
            Interlocked.Increment(ref connections);
            var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);
            try {await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback,port),token);return new NetworkStream(socket,true);}
            catch {socket.Dispose();throw;}
        }
        try {
            using(var resolver=new ExistingEntryResolver(Public,Empty,connect:Connect)){
                for(int i=1;i<=3;i++){
                    var result=(await resolver.Resolve([new(0,"http://public.example/entry?token=fixture")],"faketcp",default)).Single();
                    Check(result.Error.Length==0&&result.Endpoints.SequenceEqual(new[]{$"203.0.113.8:{45000+i}"}),"refresh obtains changed server contents over the retained connection "+i);
                }
                Check(connections==1&&reads==3,"three independent refreshes use one TCP connection rather than cached subscription contents");
                var other=(await resolver.Resolve([new(0,"http://other.example/entry?token=another-fixture")],"faketcp",default)).Single();
                Check(other.Error.Length==0&&connections==2,"changing the subscription host opens its own validated connection");
            }
            using(var next=new ExistingEntryResolver(Public,Empty,connect:Connect)){
                var result=(await next.Resolve([new(0,"http://public.example/entry")],"faketcp",default)).Single();
                Check(result.Error.Length==0&&connections==3,"a new resolver lifetime establishes a new connection after the prior owner was disposed");
                var oversized=(await next.Resolve([new(0,"http://public.example/large-error")],"faketcp",default)).Single();
                Check(oversized.Error.Contains("HTTP 503")&&!oversized.Error.Contains("上报已过期")&&!oversized.Error.Contains("must-not-leak")&&oversized.Attempts==2,"oversized chunked error bodies cannot spoof a trusted expiry code or leak response contents");
                var began=System.Diagnostics.Stopwatch.StartNew();
                var stalled=(await next.Resolve([new(0,"http://public.example/stalled-error")],"faketcp",default)).Single();
                Check(stalled.Error.Contains("HTTP 503")&&stalled.Attempts==2&&began.ElapsedMilliseconds<4000,$"stalled error details preserve the HTTP status and cannot hold the full subscription deadline ({began.ElapsedMilliseconds}ms, {stalled.Error})");
            }
        }finally{await server.StopAsync();}
    }
}
