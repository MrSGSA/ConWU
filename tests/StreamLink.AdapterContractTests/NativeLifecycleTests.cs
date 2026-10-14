using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Runtime.InteropServices;
using System.Collections.Concurrent;
using StreamLink.Core;

static class NativeLifecycleTests
{
    [DllImport("iphlpapi.dll")]static extern uint GetIfEntry2Ex(int level,IntPtr row);
    static bool Present(ulong luid) {
        // MIB_IF_ROW2 begins with NET_LUID. Oversized zeroed native storage
        // avoids guessing the remaining SDK structure layout. Query an actual
        // row, not ConvertInterfaceLuidToIndex's persistent identity mapping.
        IntPtr row=Marshal.AllocHGlobal(4096);
        try {Marshal.Copy(new byte[4096],0,row,4096);Marshal.WriteInt64(row,unchecked((long)luid));
            uint result=GetIfEntry2Ex(2,row); // MibIfEntryNormalWithoutStatistics: no NDIS counter OID
            return result switch {0=>true,2 or 1168=>false,_=>throw new IOException("Owned-LUID query failed: "+result)};
        }finally{Marshal.FreeHGlobal(row);}
    }
    static readonly JsonSerializerOptions Json=new(){WriteIndented=true};
    public static async Task Run(string components,string output,int rounds)
    {
        if(rounds is <1 or >100)throw new ArgumentOutOfRangeException(nameof(rounds));
        if(File.Exists(output)||Directory.Exists(output+".rounds"))throw new IOException("Choose a new output path; previous failure evidence is not overwritten");
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        var rows=new List<object>();string failure="";int passed=0;
        var original=NetworkInterface.GetAllNetworkInterfaces().Select(n=>n.Id).ToHashSet();
        string Hash(string file)=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file)));
        var inputs=new{test=Hash(Assembly.GetExecutingAssembly().Location),bridge=Hash(Path.Combine(components,"streamlink-tun.dll")),wintun=Hash(Path.Combine(components,"wintun.dll"))};
        try{
            for(int iteration=1;iteration<=rounds;iteration++){
                string folder=Path.Combine(output+".rounds",iteration.ToString("D3"));string resultFile=Path.Combine(folder,"result.json");
                var process=await LifecycleProcessWatchdog.Run(folder,["--native-lifecycle-child",components,"--output",resultFile,"--iteration",iteration.ToString()],TimeSpan.FromSeconds(30));
                JsonElement? result=null;if(File.Exists(resultFile)){using var document=JsonDocument.Parse(File.ReadAllText(resultFile));result=document.RootElement.Clone();}
                rows.Add(new{iteration,process,result});
                if(process.TimedOut||!process.Reaped||process.ExitCode!=0||process.Error!=null||result==null||result.Value.GetProperty("status").GetString()!="Pass")
                    throw new IOException($"Isolated lifecycle iteration {iteration} failed; inspect child stages and watchdog evidence");
                passed++;Console.WriteLine($"NATIVE-LIFECYCLE {passed}/{rounds}");
            }
            if(!original.IsSubsetOf(NetworkInterface.GetAllNetworkInterfaces().Select(n=>n.Id).ToHashSet()))throw new IOException("Pre-existing interface disappeared during test");
        }catch(Exception ex){failure=ex.ToString();throw;}
        finally{File.WriteAllText(output,JsonSerializer.Serialize(new{schemaVersion=2,status=failure.Length==0?"Pass":"Fail",rounds=passed,requestedRounds=rounds,rows,failure,inputs,
            isolatedProcessPerRound=true,sameProcessLeakGatePassed=false,
            acceptance="Original three-second I/O/close wait and immediate-owned-interface assertion remain; 30s outer watchdog is containment, not a relaxed pass threshold",
            scope="Actual official adapter iterations only when run on an authorized Windows test host. No WAN, third-party driver deletion or production service changes. Repeat same-process leak/installed-service gates separately."},Json));}
    }

    public static async Task<int> RunChild(string components,string output,int iteration,bool contractV2=false)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);string journal=Path.ChangeExtension(output,"stages.jsonl");
        object journalGate=new();var watch=Stopwatch.StartNew();string failure="";int checks=0;bool closeCompleted=false;
        using var stages=new BlockingCollection<string>(2048);
        var writer=Task.Factory.StartNew(()=>{using var stream=new StreamWriter(journal,false){AutoFlush=true};foreach(var row in stages.GetConsumingEnumerable())stream.WriteLine(row);},CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
        string? name=null;bool? presentImmediately=null;double? pnpConvergedMs=null;double? pnpQueryMs=null;
        int baselineHandles=Process.GetCurrentProcess().HandleCount;
        NativeAdapter? adapter=null;var cancel=new CancellationTokenSource();var tasks=new List<Task>();
        ulong? ownedLuid=null;
        void Stage(string phase){stages.TryAdd(JsonSerializer.Serialize(new{iteration,phase,elapsedMs=watch.Elapsed.TotalMilliseconds,thread=Environment.CurrentManagedThreadId}));}
        Task Start(Action action)=>Task.Factory.StartNew(action,CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
        try{
            var mesh=MeshIdentity.Create("https://example.com/","","faketcp");name="StreamLink-"+mesh.Pair.Network[..8]+"-1";
            Stage("create-begin:"+name);adapter=new NativeAdapter(components,mesh.Pair.Network,1);Stage("create-complete");
            typeof(NativeAdapter).GetProperty("LifecycleTrace",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(adapter,(Action<string>)Stage);
            ownedLuid=adapter.InterfaceLuid;
            bool IsPresent()=>contractV2?ownedLuid is{} luid&&Present(luid):NetworkInterface.GetAllNetworkInterfaces().Any(n=>n.Name==name);
            if(!IsPresent())throw new IOException("Owned adapter not present or actual identity unavailable");checks++;
            byte[] packet=Packet(mesh.Pair.Network,mesh.LocalIp);
            var actual=adapter;
            tasks.Add(Start(()=>{try{while(!cancel.IsCancellationRequested)actual.Read(new byte[1280],cancel.Token);}catch(Exception ex)when(ex is OperationCanceledException or ObjectDisposedException){}finally{Stage("read-exited");}}));
            tasks.Add(Start(()=>{try{while(!cancel.IsCancellationRequested){actual.Write(packet);if(cancel.Token.WaitHandle.WaitOne(2))break;}}catch(Exception ex)when(ex is OperationCanceledException or ObjectDisposedException){}finally{Stage("write-exited");}}));
            tasks.Add(Start(()=>{try{while(!cancel.IsCancellationRequested){_=actual.Statistics;if(cancel.Token.WaitHandle.WaitOne(2))break;}}catch(Exception ex)when(ex is OperationCanceledException or ObjectDisposedException){}finally{Stage("stats-exited");}}));
            // Dedicated threads eliminate a thread-pool startup assumption; this
            // changes the fixture, not the production close contract.
            var written=Stopwatch.StartNew();while(actual.Statistics.WrittenPackets==0&&written.Elapsed<TimeSpan.FromSeconds(1))await Task.Delay(5);
            if(actual.Statistics.WrittenPackets==0)throw new IOException("Native writes were not recorded");checks++;Stage("close-requested");
            tasks.Add(Start(()=>{actual.Dispose();closeCompleted=true;Stage("dispose-returned");}));
            tasks.Add(Start(()=>{Stage("cancel-requested");cancel.Cancel();Stage("cancel-returned");}));
            await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(3));checks++;Stage("io-and-close-complete");
            actual.Stop();actual.Dispose();bool rejected=false;try{_=actual.Statistics;}catch(ObjectDisposedException){rejected=true;}
            if(!rejected)throw new IOException("Late statistics did not reject released resource");checks++;
            var queryTime=Stopwatch.StartNew();presentImmediately=IsPresent();pnpQueryMs=queryTime.Elapsed.TotalMilliseconds;
            Stage(presentImmediately.Value?"owned-visible-after-close":"owned-absent-after-close");
            if(presentImmediately.Value){
                var pnp=Stopwatch.StartNew();while(pnp.Elapsed<TimeSpan.FromSeconds(5)){
                    await Task.Delay(100);if(!IsPresent()){pnpConvergedMs=pnp.Elapsed.TotalMilliseconds;break;}
                }
                // Keep the historical assertion as a Fail even if PnP later
                // converges. Convergence is evidence, not a retroactive pass.
                if(!contractV2)throw new IOException("Owned adapter remains immediately after close; delayed PnP convergence recorded separately");
                if(pnpConvergedMs==null||pnpConvergedMs>5000)throw new IOException("Contract v2: owned interface did not converge within the separate five-second observation window");
            }
            checks++;
        }catch(Exception ex){failure=ex.ToString();Stage("failure:"+ex.GetType().Name);}
        finally{
            if(adapter!=null&&!closeCompleted){
                Stage("bounded-cleanup-requested");var actual=adapter;
                var cleanup=Start(()=>{cancel.Cancel();actual.Dispose();closeCompleted=true;});
                try{await cleanup.WaitAsync(TimeSpan.FromSeconds(3));}
                catch(Exception ex){failure+=(failure.Length==0?"":"\n")+"Cleanup incomplete: "+ex;Stage("cleanup-incomplete-resource-retained-until-child-exit");}
            }
            int? finalHandles=null;try{finalHandles=Process.GetCurrentProcess().HandleCount;}catch{}
            stages.CompleteAdding();try{await writer.WaitAsync(TimeSpan.FromSeconds(2));}catch(Exception ex){failure+=" Journal did not finish: "+ex.Message;}
            File.WriteAllText(output,JsonSerializer.Serialize(new{schemaVersion=contractV2?3:2,acceptanceVersion=contractV2?"lifecycle-v2":"historical-immediate-pnp",status=failure.Length==0?"Pass":"Fail",iteration,checks,failure,closeCompleted,name,ownedLuid,
                queryKind=contractV2?"IPHelper-owned-LUID":"Global-NetworkInterface-PnP-enumeration",presentImmediately,queryMs=pnpQueryMs,interfaceConvergedMs=pnpConvergedMs,
                fullPnpQueryPerformed=!contractV2,baselineHandles,finalHandles,elapsedMs=watch.Elapsed.TotalMilliseconds},Json));
            // Never synchronously Dispose the adapter again here. The parent
            // supervises a stuck native call; it must not block in our finally.
        }
        return failure.Length==0?0:1;
    }

    public static async Task RunV2(string components,string output,int rounds)
    {
        if(rounds is<1 or>100)throw new ArgumentOutOfRangeException(nameof(rounds));
        if(File.Exists(output)||Directory.Exists(output+".child"))throw new IOException("Use fresh evidence paths");
        var process=await LifecycleProcessWatchdog.Run(output+".child",["--native-lifecycle-v2-child",components,"--output",output,"--rounds",rounds.ToString()],TimeSpan.FromSeconds(rounds*30+5));
        File.WriteAllText(output+".watchdog.json",JsonSerializer.Serialize(process,Json));
        if(process.TimedOut||!process.Reaped||process.ExitCode!=0||process.Error!=null)throw new IOException("Same-process lifecycle v2 failed; inspect stages/watchdog, no automatic rerun");
    }
    public static async Task<int> RunV2Child(string components,string output,int rounds)
    {
        var rows=new List<JsonElement>();var original=NetworkInterface.GetAllNetworkInterfaces().Select(n=>n.Id).ToHashSet();
        int code=0;
        for(int i=1;i<=rounds;i++) {
            string result=Path.Combine(output+".rounds",i.ToString("D3"),"result.json");
            code=await RunChild(components,result,i,contractV2:true);
            using var doc=JsonDocument.Parse(File.ReadAllText(result));rows.Add(doc.RootElement.Clone());
            Console.WriteLine($"LIFECYCLE-V2 {i}/{rounds} {(code==0?"Pass":"Fail")}");if(code!=0)break;
        }
        bool foreignPresent=original.IsSubsetOf(NetworkInterface.GetAllNetworkInterfaces().Select(n=>n.Id).ToHashSet());
        if(!foreignPresent)code=1;
        File.WriteAllText(output,JsonSerializer.Serialize(new{schemaVersion=3,status=code==0?"Pass":"Fail",acceptanceVersion="lifecycle-v2",requestedRounds=rounds,completedRounds=rows.Count,
            isolatedProcessPerRound=false,sameLongLivedProcess=true,pid=Environment.ProcessId,preExistingInterfacesPreserved=foreignPresent,rows,
            scope="Official Wintun only; unchanged three-second I/O+close threshold; separately timed PnP query/convergence; historic immediate-absence Fail is not overwritten; not self-TUN kernel or public 100-round evidence"},Json));
        return code;
    }

    static byte[] Packet(string network,string localIp)
    {
        byte[] packet=new byte[20];packet[0]=0x45;packet[3]=20;packet[8]=64;packet[9]=253;
        IPAddress.Parse(MeshIdentity.Address(network,2)).GetAddressBytes().CopyTo(packet,12);IPAddress.Parse(localIp).GetAddressBytes().CopyTo(packet,16);
        uint sum=0;for(int i=0;i<20;i+=2)sum+=BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(i));while(sum>65535)sum=(sum&65535)+(sum>>16);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10),(ushort)~sum);return packet;
    }

    public static async Task WatchdogSelfTest(string output)
    {
        string folder=Path.GetFullPath(output)+".child";
        var result=await LifecycleProcessWatchdog.Run(folder,["--lifecycle-watchdog-hang"],TimeSpan.FromMilliseconds(1500));
        bool ok=result.TimedOut&&result.Reaped&&result.Error==null;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
        File.WriteAllText(output,JsonSerializer.Serialize(new{status=ok?"Pass":"Fail",result,scope="Supervisor negative self-test only; intentionally stuck own child; no adapter/driver loaded"},Json));
        if(!ok)throw new IOException("Watchdog self-test failed");
    }
}
