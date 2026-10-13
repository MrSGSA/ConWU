using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using StreamLink.Core;

static class NativeLifecycleTests
{
    public static async Task Run(string components,string output,int rounds)
    {
        if(rounds is < 1 or > 100)throw new ArgumentOutOfRangeException(nameof(rounds));
        var rows=new List<object>();int checks=0;string failure="";
        var original=NetworkInterface.GetAllNetworkInterfaces().Select(n=>n.Id).ToHashSet();
        try {
            for(int iteration=0;iteration<rounds;iteration++){
                var mesh=MeshIdentity.Create("https://example.com/","","faketcp");string name="StreamLink-"+mesh.Pair.Network[..8]+"-1";
                var watch=Stopwatch.StartNew();using var adapter=new NativeAdapter(components,mesh.Pair.Network,1);
                typeof(NativeAdapter).GetProperty("LifecycleTrace",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!.SetValue(adapter,(Action<string>)(stage=>Console.WriteLine($"CLOSE {iteration+1} {watch.ElapsedMilliseconds}ms {stage}")));
                if(!NetworkInterface.GetAllNetworkInterfaces().Any(n=>n.Name==name))throw new Exception("Owned adapter not present");checks++;
                byte[] packet=new byte[20];packet[0]=0x45;packet[2]=0;packet[3]=20;packet[8]=64;packet[9]=253;
                IPAddress.Parse(MeshIdentity.Address(mesh.Pair.Network,2)).GetAddressBytes().CopyTo(packet,12);IPAddress.Parse(mesh.LocalIp).GetAddressBytes().CopyTo(packet,16);
                uint sum=0;for(int i=0;i<20;i+=2)sum+=BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(i));while(sum>65535)sum=(sum&65535)+(sum>>16);BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10),(ushort)~sum);
                using var cancel=new CancellationTokenSource();
                var read=Task.Run(()=>{try{while(!cancel.IsCancellationRequested)adapter.Read(new byte[1280],cancel.Token);}catch(Exception ex)when(ex is OperationCanceledException or ObjectDisposedException){}});
                var write=Task.Run(async()=>{try{while(!cancel.IsCancellationRequested){adapter.Write(packet);await Task.Delay(2,cancel.Token);}}catch(Exception ex)when(ex is OperationCanceledException or ObjectDisposedException){}});
                var stats=Task.Run(async()=>{try{while(!cancel.IsCancellationRequested){_=adapter.Statistics;await Task.Delay(2,cancel.Token);}}catch(Exception ex)when(ex is OperationCanceledException or ObjectDisposedException){}});
                try {
                    await Task.Delay(25);var before=adapter.Statistics;if(before.WrittenPackets==0)throw new Exception("Native writes were not recorded");checks++;
                    var close=Task.Run(adapter.Dispose);cancel.Cancel();
                    await Task.WhenAll(read,write,stats,close).WaitAsync(TimeSpan.FromSeconds(3));checks++;
                    adapter.Stop();adapter.Dispose();bool rejected=false;try{_=adapter.Statistics;}catch(ObjectDisposedException){rejected=true;}
                    if(!rejected)throw new Exception("Late stats did not reject the freed resource");checks++;
                }finally{cancel.Cancel();adapter.Dispose();await Task.WhenAll(read,write,stats).WaitAsync(TimeSpan.FromSeconds(3));}
                if(NetworkInterface.GetAllNetworkInterfaces().Any(n=>n.Name==name))throw new Exception("Owned adapter remains after close");checks++;
                rows.Add(new{iteration=iteration+1,elapsedMs=watch.Elapsed.TotalMilliseconds,concurrentReadWriteStatsClose=true});
                if(iteration%10==9)Console.WriteLine("NATIVE-LIFECYCLE "+(iteration+1)+"/"+rounds);
            }
            if(!original.IsSubsetOf(NetworkInterface.GetAllNetworkInterfaces().Select(n=>n.Id).ToHashSet()))throw new Exception("Pre-existing interface disappeared during test");checks++;
        }catch(Exception ex){failure=ex.ToString();throw;}
        finally {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
            File.WriteAllText(output,JsonSerializer.Serialize(new{status=failure.Length==0?"Pass":"Fail",checks,rounds=rows.Count,rows,failure,scope="Actual official Wintun/bridge creation, owned IPv4, concurrent read/write/statistics/cancel/close, 100-cycle limit and exact adapter teardown. Unknown IP protocol 253 is delivered locally only. No remote business, custom driver, user route deletion or existing service change."},new JsonSerializerOptions{WriteIndented=true}));
        }
    }
}
