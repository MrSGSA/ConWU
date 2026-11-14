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
        var inputs=new{test=Hash(Assembly.GetExecutingAssembly().Location),bridge=Hash(Path.Combine(components,"conwu-tun.dll")),wintun=Hash(Path.Combine(components,"wintun.dll"))};
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

    public static async Task<int> RunChild(string components,string output,int iteration,bool contractV2=false,bool splitAxes=false)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);string journal=Path.ChangeExtension(output,"stages.jsonl");
        object journalGate=new();var watch=Stopwatch.StartNew();string failure="";int checks=0;bool closeCompleted=false;
        using var stages=new BlockingCollection<string>(2048);
        var writer=Task.Factory.StartNew(()=>{using var stream=new StreamWriter(journal,false){AutoFlush=true};foreach(var row in stages.GetConsumingEnumerable())stream.WriteLine(row);},CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
        string? name=null;bool? presentImmediately=null;double? pnpConvergedMs=null;double? pnpQueryMs=null;
        int baselineHandles=Process.GetCurrentProcess().HandleCount;
        NativeAdapter? adapter=null;var cancel=new CancellationTokenSource();var tasks=new List<Task>();
        ulong? ownedLuid=null;bool performancePass=false,resourceSafety=false;double? closeElapsedMs=null;
        void Stage(string phase){stages.TryAdd(JsonSerializer.Serialize(new{iteration,phase,elapsedMs=watch.Elapsed.TotalMilliseconds,thread=Environment.CurrentManagedThreadId}));}
        Task Start(Action action)=>Task.Factory.StartNew(action,CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
        try{
            var mesh=MeshIdentity.Create("https://example.com/","","faketcp");name="StreamLink-"+mesh.Pair.Network[..8]+"-1";
            Stage("create-begin:"+name);adapter=new NativeAdapter(components,mesh.Pair.Network,1,Stage);Stage("create-complete");
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
            var closeWatch=Stopwatch.StartNew();
            tasks.Add(Start(()=>{actual.Dispose();closeCompleted=true;Stage("dispose-returned");}));
            tasks.Add(Start(()=>{Stage("cancel-requested");cancel.Cancel();Stage("cancel-returned");}));
            var all=Task.WhenAll(tasks);
            try{await all.WaitAsync(TimeSpan.FromSeconds(3));performancePass=true;}
            catch(TimeoutException)when(splitAxes){
                // Preserve the three-second Fail. This finite observation joins
                // the SAME owner; it grants no performance exception or second close.
                failure="PerformanceGate: original three-second I/O+close deadline exceeded";Stage("performance-fail-3s");
                await all.WaitAsync(TimeSpan.FromSeconds(5));
            }
            closeElapsedMs=closeWatch.Elapsed.TotalMilliseconds;
            if(splitAxes && closeElapsedMs>3000){performancePass=false;failure="PerformanceGate: monotonic I/O+close elapsed exceeds original three-second deadline";}
            checks++;Stage("io-and-close-complete");
            actual.Stop();actual.Dispose();bool rejected=false;try{_=actual.Statistics;}catch(ObjectDisposedException){rejected=true;}
            if(!rejected)throw new IOException("Late statistics did not reject released resource");checks++;
            resourceSafety=all.IsCompletedSuccessfully&&closeCompleted&&rejected;
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
            if(adapter!=null&&!closeCompleted&&!splitAxes){
                Stage("bounded-cleanup-requested");var actual=adapter;
                var cleanup=Start(()=>{cancel.Cancel();actual.Dispose();closeCompleted=true;});
                try{await cleanup.WaitAsync(TimeSpan.FromSeconds(3));}
                catch(Exception ex){failure+=(failure.Length==0?"":"\n")+"Cleanup incomplete: "+ex;Stage("cleanup-incomplete-resource-retained-until-child-exit");}
            }
            int? finalHandles=null;try{finalHandles=Process.GetCurrentProcess().HandleCount;}catch{}
            stages.CompleteAdding();try{await writer.WaitAsync(TimeSpan.FromSeconds(2));}catch(Exception ex){failure+=" Journal did not finish: "+ex.Message;}
            File.WriteAllText(output,JsonSerializer.Serialize(new{schemaVersion=splitAxes?4:contractV2?3:2,acceptanceVersion=splitAxes?"PF2-02-separated-axes":contractV2?"lifecycle-v2":"historical-immediate-pnp",status=failure.Length==0?"Pass":"Fail",iteration,checks,failure,closeCompleted,name,ownedLuid,
                performanceGate=performancePass?"Pass":"Fail",resourceSafety=resourceSafety?"Pass":"NotProven",completion=closeCompleted?"Complete":"Incomplete",closeElapsedMs,
                queryKind=contractV2?"IPHelper-owned-LUID":"Global-NetworkInterface-PnP-enumeration",presentImmediately,queryMs=pnpQueryMs,interfaceConvergedMs=pnpConvergedMs,
                fullPnpQueryPerformed=!contractV2,baselineHandles,finalHandles,elapsedMs=watch.Elapsed.TotalMilliseconds},Json));
            // Never synchronously Dispose the adapter again here. The parent
            // supervises a stuck native call; it must not block in our finally.
        }
        return failure.Length==0?0:1;
    }

    public static async Task RunPf2(string components,string output,bool child=false)
    {
        if(!child){
            if(File.Exists(output)||Directory.Exists(output+".rounds"))throw new IOException("Fresh evidence required");
            var process=await LifecycleProcessWatchdog.Run(output+".child",["--native-lifecycle-pf2-child",components,"--output",output],TimeSpan.FromSeconds(65));
            File.WriteAllText(output+".watchdog.json",JsonSerializer.Serialize(process,Json));
            if(process.TimedOut||!process.Reaped||process.Error!=null)throw new IOException("Owned child containment failure; inspect watchdog");
            Environment.ExitCode=process.ExitCode??1;return;
        }
        var rows=new List<JsonElement>();
        // Two sequential owners in the same process: the second create is
        // allowed only after the first actual close and I/O completion.
        for(int i=1;i<=2;i++){
            string file=Path.Combine(output+".rounds",i.ToString("D3"),"result.json");
            await RunChild(components,file,i,contractV2:true,splitAxes:true);
            using var d=JsonDocument.Parse(File.ReadAllText(file));var row=d.RootElement.Clone();rows.Add(row);
            if(row.GetProperty("resourceSafety").GetString()!="Pass"||row.GetProperty("completion").GetString()!="Complete"||!PnpComplete(row))break;
        }
        var axes=Summarize(rows);
        File.WriteAllText(output,JsonSerializer.Serialize(new{schemaVersion=5,status=axes.Passed?"Pass":"Fail",performanceGate=axes.Performance?"Pass":"Fail",performanceCoverage=rows.Count==2?"TwoRounds":"Partial",observedRounds=rows.Count,
            resourceSafety=axes.ResourceSafety?"Pass":"NotProven",completion=axes.Complete?"Complete":"Incomplete",pnpConvergence=axes.Pnp?"Pass":"NotProven",reopen=axes.Reopen?"Pass":"NotProven",rows,
            originalThresholdSeconds=3,boundedCompletionObservationAdditionalSeconds=5,officialWintun=true,personalPerformanceExceptionAccepted=false,
            scope="Two real official adapters, sequential owners in one child. Historical 3.61s Fail unchanged; safety is separate from latency; not self-TUN."},Json));
        Environment.ExitCode=axes.Passed?0:1;
    }

    static bool PnpComplete(JsonElement row)=>row.GetProperty("presentImmediately").ValueKind==JsonValueKind.False||
        (row.GetProperty("interfaceConvergedMs").ValueKind==JsonValueKind.Number&&row.GetProperty("interfaceConvergedMs").TryGetDouble(out double ms)&&ms is >=0 and <=5000);
    sealed record LifecycleAxes(bool Performance,bool ResourceSafety,bool Complete,bool Pnp,bool Reopen,bool Passed);
    static LifecycleAxes Summarize(IReadOnlyList<JsonElement> rows){
        bool observed=rows.Count>0;
        bool performance=observed&&rows.All(r=>r.GetProperty("performanceGate").GetString()=="Pass");
        bool safe=observed&&rows.All(r=>r.GetProperty("resourceSafety").GetString()=="Pass");
        bool complete=observed&&rows.All(r=>r.GetProperty("completion").GetString()=="Complete");
        bool pnp=observed&&rows.All(PnpComplete);
        bool reopened=rows.Count==2&&safe&&complete&&pnp;
        return new(performance,safe,complete,pnp,reopened,reopened&&performance&&rows.All(r=>r.GetProperty("status").GetString()=="Pass"));
    }
    public static void AxesContractTest(string output){
        if(File.Exists(output))throw new IOException("Fresh evidence required");
        JsonElement Row(bool performance=true,bool safe=true,bool pnp=true,string? status=null)=>JsonSerializer.SerializeToElement(new{
            status=status??(performance&&safe&&pnp?"Pass":"Fail"),performanceGate=performance?"Pass":"Fail",resourceSafety=safe?"Pass":"NotProven",completion=safe?"Complete":"Incomplete",
            presentImmediately=!pnp,interfaceConvergedMs=(double?)null});
        var cases=new[]{
            ("both completed and converged",new[]{Row(),Row()},true,true,true),
            ("second PnP timeout cannot become top-level Pass",new[]{Row(),Row(pnp:false)},false,true,false),
            ("safe slow close keeps performance Fail",new[]{Row(performance:false),Row()},false,true,true),
            ("first round safety is not overwritten",new[]{Row(safe:false),Row()},false,false,false),
            ("partial coverage does not prove reopen",new[]{Row()},false,true,false),
            ("other child failure is not ignored",new[]{Row(),Row(status:"Fail")},false,true,true),
            ("no observed owner proves nothing",Array.Empty<JsonElement>(),false,false,false)};
        var results=cases.Select(c=>{var a=Summarize(c.Item2);if(a.Passed!=c.Item3||a.ResourceSafety!=c.Item4||a.Reopen!=c.Item5)throw new Exception(c.Item1);return new{test=c.Item1,axes=a};}).ToArray();
        File.WriteAllText(output,JsonSerializer.Serialize(new{status="Pass",checks=results.Length,results,scope="Lifecycle aggregation regression only; no adapter or driver loaded; original 3s and 5s thresholds unchanged"},Json));
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
