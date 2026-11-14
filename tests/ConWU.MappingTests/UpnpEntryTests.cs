using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;
using StreamLink.Core;

static class UpnpEntryTests
{
    internal static async Task Run(Action<bool,string> check)
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(30)); var token=stop.Token;
        async Task Until(Func<bool> ready) { for(int i=0;!ready();i++){if(i>300)throw new TimeoutException("UPnP fixture did not recover");await Task.Delay(15,token);} }
        await using(var fixture=new Gateway()) {
            fixture.Rules[41420]=new(41420,9999,"127.0.0.2","TCP","Foreign application");
            var foreign=fixture.Rules[41420];
            await using var mapping=await UpnpMapping.Create(41420,()=>[IPAddress.Loopback],fixture.Discover,_=>{},token,TimeSpan.FromMilliseconds(80));
            check(mapping.IsValid&&mapping.PublicEndpoint.Address.Equals(fixture.External)&&mapping.PublicEndpoint.Port!=41420,
                "direct UPnP entry works without STUN and publishes its actually reserved alternative port");
            check(fixture.Rules[41420]==foreign,"occupied gateway rule is preserved");
            int changes=0;mapping.Changed+=_=>changes++;var task=mapping.Maintain(token);
            int oldPort=mapping.PublicEndpoint.Port;
            fixture.Rules[oldPort]=new(oldPort,9998,"127.0.0.2","TCP","Foreign after reboot");
            fixture.External=IPAddress.Parse("112.38.216.25");
            ((IMappingRefresh)mapping).RequestRefresh();
            await Until(()=>mapping.PublicEndpoint.Port!=oldPort&&mapping.PublicEndpoint.Address.Equals(fixture.External));
            check(changes==1&&mapping.IsValid&&!task.IsCompleted&&fixture.Rules[oldPort].Description=="Foreign after reboot",
                "gateway restart/reassignment refresh changes the published endpoint without replacing foreign ownership");
            fixture.FailAdds=1;int attempts=fixture.Adds;((IMappingRefresh)mapping).RequestRefresh();
            await Until(()=>fixture.Adds>attempts);
            check(mapping.IsValid&&!task.IsCompleted&&fixture.Rules.ContainsKey(mapping.PublicEndpoint.Port),"transient UPnP renewal failure retains the still valid grant and maintenance");
            fixture.FailAdds=0;((IMappingRefresh)mapping).RequestRefresh();
            await Until(()=>fixture.Adds>attempts+1);
            int owned=mapping.PublicEndpoint.Port;await mapping.DisposeAsync();
            check(!mapping.IsValid&&!fixture.Rules.ContainsKey(owned)&&fixture.Rules.ContainsKey(oldPort)&&fixture.Rules[41420]==foreign,
                "UPnP shutdown deletes only its current owned grant and stops refresh work");
        }
        await using(var fixture=new Gateway {External=IPAddress.Parse("10.190.165.5")}) {
            bool rejected=false;
            try {await using var mapping=await UpnpMapping.Create(41421,()=>[IPAddress.Loopback],fixture.Discover,_=>{},token);}
            catch(IOException){rejected=true;}
            check(rejected&&fixture.Adds==0,"private WAN address is not spliced into a public candidate or given a misleading direct grant");
        }
        await using(var fixture=new Gateway()) {
            await using var mapping=await UpnpMapping.Create(41422,()=>[IPAddress.Loopback],fixture.Discover,_=>{},token,TimeSpan.FromMilliseconds(50));
            int adds=fixture.Adds;var task=mapping.Maintain(token);fixture.Rules.Clear();((IMappingRefresh)mapping).RequestRefresh();
            await Until(()=>fixture.Adds>adds&&fixture.Rules.ContainsKey(41422));
            check(mapping.IsValid&&mapping.PublicEndpoint.Port==41422,"lost gateway rule is recreated with the same local listener and owner");
            fixture.External=IPAddress.Parse("100.64.0.2");((IMappingRefresh)mapping).RequestRefresh();
            await Until(()=>task.IsCompleted);
            check(task.IsFaulted&&!mapping.IsValid,"a newly private WAN withdraws the old public candidate immediately");
        }
        await using(var fixture=new Gateway()) {
            using var canceled=new CancellationTokenSource();canceled.Cancel();bool rejected=false;
            try {await using var mapping=await UpnpMapping.Create(41423,()=>[IPAddress.Loopback],fixture.Discover,_=>{},canceled.Token);}
            catch(OperationCanceledException){rejected=true;}
            check(rejected&&fixture.Adds==0,"canceled gateway creation does not open any mapping");
        }
    }
    sealed class Gateway:IAsyncDisposable
    {
        readonly TcpListener listener=new(IPAddress.Loopback,0);
        readonly CancellationTokenSource stop=new();readonly Task running;
        public readonly ConcurrentDictionary<int,RouterMapping> Rules=new();
        public IPAddress External=IPAddress.Parse("112.38.216.24");public int Adds,Deletes,FailAdds;
        public Gateway(){listener.Start();running=Serve();}
        public async IAsyncEnumerable<RouterService> Discover(IPAddress local,[System.Runtime.CompilerServices.EnumeratorCancellation]CancellationToken token){token.ThrowIfCancellationRequested();await Task.Yield();yield return new(new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/control"),"urn:schemas-upnp-org:service:WANIPConnection:1",local);}
        async Task Serve()
        {
            try {while(true){using var client=await listener.AcceptTcpClientAsync(stop.Token);using var stream=client.GetStream();using var reader=new StreamReader(stream,Encoding.UTF8,leaveOpen:true);
                await reader.ReadLineAsync(stop.Token);string action="";int length=0;
                while(await reader.ReadLineAsync(stop.Token) is {Length:>0} line){if(line.StartsWith("SOAPAction:",StringComparison.OrdinalIgnoreCase))action=line;if(line.StartsWith("Content-Length:",StringComparison.OrdinalIgnoreCase))length=int.Parse(line[15..]);}
                char[] body=new char[length];if(await reader.ReadBlockAsync(body.AsMemory(),stop.Token)!=length)throw new EndOfStreamException();var doc=XDocument.Parse(new string(body));
                string Value(string key)=>doc.Descendants().First(x=>x.Name.LocalName==key).Value;
                string xml="<root/>";int status=200;
                if(action.Contains("GetExternalIPAddress"))xml=$"<root><NewExternalIPAddress>{External}</NewExternalIPAddress></root>";
                else {
                    int port=int.Parse(Value("NewExternalPort"));
                    if(action.Contains("GetSpecificPortMappingEntry"))xml=Rules.TryGetValue(port,out var rule)?$"<root><NewInternalPort>{rule.InternalPort}</NewInternalPort><NewInternalClient>{rule.InternalClient}</NewInternalClient><NewPortMappingDescription>{rule.Description}</NewPortMappingDescription></root>":"<root><errorCode>714</errorCode></root>";
                    else if(action.Contains("AddPortMapping")){Interlocked.Increment(ref Adds);if(Interlocked.Decrement(ref FailAdds)>=0){status=500;xml="<root><errorCode>501</errorCode></root>";}else Rules[port]=new(port,int.Parse(Value("NewInternalPort")),Value("NewInternalClient"),Value("NewProtocol"),Value("NewPortMappingDescription"));}
                    else if(action.Contains("DeletePortMapping")){Rules.TryRemove(port,out _);Interlocked.Increment(ref Deletes);}
                }
                byte[] bytes=Encoding.UTF8.GetBytes(xml);await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {status} Fixture\r\nContent-Type: text/xml\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n"),stop.Token);await stream.WriteAsync(bytes,stop.Token);
            }}catch(Exception error)when(stop.IsCancellationRequested&&error is OperationCanceledException or ObjectDisposedException or SocketException){}
        }
        public async ValueTask DisposeAsync(){stop.Cancel();listener.Stop();await running;stop.Dispose();}
    }
}
