using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using StreamLink.Core;

static partial class Program
{
    static async Task SustainedRawLoad(string binary,int seconds,string output)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
        if(seconds is <30 or >3600)throw new ArgumentOutOfRangeException(nameof(seconds));
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");var guest=Guest(owner);guest.Directory=owner.Directory;
        using var a=new LoadAdapter();using var b=new LoadAdapter();
        await using var ra=new MeshRouter(owner,a);await using var rb=new MeshRouter(guest,b);
        await using var wire=new RawLoopback(binary,owner,ra.LocalEndpoint,rb.LocalEndpoint);
        ra.SetCandidate(2,wire.Client(1,2),"B","");rb.SetCandidate(1,wire.Client(2,1),"A","");
        await Until(()=>ra.HasHealthyPath(2)&&rb.HasHealthyPath(1),"sustained test authenticates both directions over real native FakeTCP+HTTP loops");
        using var stop=new CancellationTokenSource();
        // Forty inner Mbps each way, in small timed batches. Both source queues
        // are bounded: a slow consumer never accumulates minutes of stale video.
        Task Feed(LoadAdapter adapter,string from,string to)=>Task.Run(async()=>{
            using var ticks=new PeriodicTimer(TimeSpan.FromMilliseconds(5));
            while(await ticks.WaitForNextTickAsync(stop.Token)) {
                for(int i=0;i<19;i++) {
                    byte[] packet=Packet(from,to,MeshLink.Mtu);packet.AsSpan(28).Fill(0x6d);
                    if(adapter.Outgoing.TryAdd(packet))Interlocked.Increment(ref adapter.Offered);
                    else Interlocked.Increment(ref adapter.SourceDrops);
                }
            }
        });
        var feeds=new[]{Feed(a,owner.LocalIp,guest.LocalIp),Feed(b,guest.LocalIp,owner.LocalIp)};
        var clock=Stopwatch.StartNew();var rows=new List<object>();var healthTransitions=new List<object>();
        bool unhealthy=false,lastAHealthy=true,lastBHealthy=true;long worstGap=0;
        using var process=Process.GetCurrentProcess();string failure="";
        try {
            long nextReport=10000;
            while(clock.Elapsed.TotalSeconds<seconds) {
                await Task.Delay(250);
                if(ra.Completion.IsCompleted)await ra.Completion;if(rb.Completion.IsCompleted)await rb.Completion;
                bool aHealthy=ra.HasHealthyPath(2),bHealthy=rb.HasHealthyPath(1);
                unhealthy|=!aHealthy||!bHealthy;
                if(aHealthy!=lastAHealthy||bHealthy!=lastBHealthy){
                    healthTransitions.Add(new{seconds=clock.Elapsed.TotalSeconds,aHealthy,bHealthy,a=ra.Status().Single().Liveness,b=rb.Status().Single().Liveness});
                    lastAHealthy=aHealthy;lastBHealthy=bHealthy;
                }
                long now=Environment.TickCount64;
                if(a.LastReceive!=0&&b.LastReceive!=0)worstGap=Math.Max(worstGap,Math.Max(now-a.LastReceive,now-b.LastReceive));
                if(clock.ElapsedMilliseconds>=nextReport) {
                    var ap=ra.Status().Single();var bp=rb.Status().Single();process.Refresh();
                    rows.Add(new {seconds=clock.Elapsed.TotalSeconds,aReceivedBytes=a.Bytes,bReceivedBytes=b.Bytes,
                        aSentBytes=ap.SentBytes,bSentBytes=bp.SentBytes,aDropped=ap.DroppedPackets,bDropped=bp.DroppedPackets,
                        aOfferedPackets=a.Offered,bOfferedPackets=b.Offered,aSourceReadPackets=a.ReadPackets,bSourceReadPackets=b.ReadPackets,
                        aSourceDrops=a.SourceDrops,bSourceDrops=b.SourceDrops,workingSetBytes=process.WorkingSet64,
                        aLiveness=ap.Liveness,bLiveness=bp.Liveness});
                    Console.WriteLine($"SOAK {clock.Elapsed.TotalSeconds:F0}/{seconds}s rx={a.Bytes}/{b.Bytes} healthy={!unhealthy} gapMs={worstGap}");
                    nextReport+=10000;
                }
            }
        } catch(Exception ex){failure=ex.ToString();}
        finally {
            stop.Cancel();foreach(var feed in feeds)try{await feed;}catch(OperationCanceledException){}
        }
        await Task.Delay(500);
        bool pass=failure.Length==0&&!unhealthy&&a.Bytes>1_000_000&&b.Bytes>1_000_000&&a.Invalid==0&&b.Invalid==0&&worstGap<5000&&wire.SawHttp;
        await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new {
            status=pass?"Pass":"Fail",requestedSeconds=seconds,elapsedSeconds=clock.Elapsed.TotalSeconds,
            sourceNominalInnerMbpsEachDirection=19*1280*8/0.005/1_000_000,
            aOfferedPackets=a.Offered,bOfferedPackets=b.Offered,aOfferedMbps=a.Offered*1280*8/clock.Elapsed.TotalSeconds/1_000_000,
            bOfferedMbps=b.Offered*1280*8/clock.Elapsed.TotalSeconds/1_000_000,aSourceReadPackets=a.ReadPackets,bSourceReadPackets=b.ReadPackets,
            aPendingSourcePackets=a.Outgoing.Count,bPendingSourcePackets=b.Outgoing.Count,
            aReceivedBytes=a.Bytes,bReceivedBytes=b.Bytes,aReceivedMbps=a.Bytes*8/clock.Elapsed.TotalSeconds/1_000_000,
            bReceivedMbps=b.Bytes*8/clock.Elapsed.TotalSeconds/1_000_000,aSourceDrops=a.SourceDrops,bSourceDrops=b.SourceDrops,
            unexpectedUnhealthy=unhealthy,invalidPayloads=a.Invalid+b.Invalid,worstSampledReceiveGapMs=worstGap,httpObserved=wire.SawHttp,
            rows,healthTransitions,wire=wire.Counters,failure,scope="production MeshRouter + AES-GCM MeshLink + native udp2raw FakeTCP HTTP/event loops; bounded memory adapters and loopback raw-wire replacement; no Wintun/WinDivert/WAN/QoS/application frames; loss and throughput are observations, not physical quality acceptance"
        },new JsonSerializerOptions{WriteIndented=true}));
        Check(pass,"sustained native-loopback data retains bidirectional liveness without a five second stall");
    }
    sealed class LoadAdapter:IPacketAdapter
    {
        public readonly BlockingCollection<byte[]> Outgoing=new(256);
        public long Bytes,Offered,ReadPackets,SourceDrops,LastReceive;public int Invalid;int disposed;
        public int Read(byte[] buffer){if(!Outgoing.TryTake(out var packet,50))return 0;Interlocked.Increment(ref ReadPackets);packet.CopyTo(buffer,0);return packet.Length;}
        public bool Write(byte[] packet){
            if(packet.Length!=MeshLink.Mtu||packet.AsSpan(28).IndexOfAnyExcept((byte)0x6d)>=0)Interlocked.Increment(ref Invalid);
            Interlocked.Add(ref Bytes,packet.Length);Interlocked.Exchange(ref LastReceive,Environment.TickCount64);return true;
        }
        public void Dispose(){if(Interlocked.Exchange(ref disposed,1)==0)Outgoing.Dispose();}
    }
}
