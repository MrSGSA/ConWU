using System.Buffers.Binary;
using System.Security.Cryptography;

namespace StreamLink.Core;

public sealed record PathDeliveryReport(Guid RequestId, Guid SendEpoch, ulong FirstSequence, ulong LastSequence,
    long StartedMs, long EndedMs, long AcceptedPackets, long AcceptedBytes, long? PeerDeliveredPackets,
    long? PeerDeliveredBytes, int ReceiverSettleMs, string Result)
{
    public double? DeficitAtReceiptPercent => PeerDeliveredPackets == null || AcceptedPackets == 0 ? null :
        100d * (AcceptedPackets - PeerDeliveredPackets.Value) / AcceptedPackets;
}
public sealed record PathDeliverySnapshot(PathDeliveryReport[] Reports, int WaitingReports, int ReceiverRequests,
    int RetainedReceiveRecords, long Deferred, long InvalidControls, long QueuedControls)
{
    public string Evidence => "AuthenticatedPathDeliveryAtReceiptCutoff";
}

// Only used after bilateral/coordinator opt-in and selected-path authentication.
// No data retransmission, delivery wait, or remote socket. The range counts
// delivered inner IP packets on this exact path and AEAD epoch, not all packets
// between two global MeshLink sequence numbers (which also include controls).
internal sealed class PathDeliveryFeedback
{
    internal const int FrameSize = 128, IntervalMs = 2000, SettleMs = 1000, DeadlineMs = 8000, HistorySize = 16384;
    readonly byte[] scope;
    readonly (ulong Sequence, int Bytes)[] received = new (ulong, int)[HistorySize];
    readonly Dictionary<Guid, Pending> pending = [];
    readonly Dictionary<Guid, Incoming> incoming = [];
    readonly Queue<PathDeliveryReport> reports = [];
    readonly Dictionary<Guid,(byte[] Digest,long At)> completed = [];
    Guid? sendEpoch, receiveEpoch;
    ulong receiveLowWater;
    ulong highestReceived;
    int receiveCursor, receiveCount;
    Segment? current;
    long deferred, invalid, sentControls;
    sealed class Segment(Guid epoch, ulong first, long now)
    {
        public readonly Guid Epoch = epoch;
        public readonly ulong First = first;
        public readonly long Started = now;
        public ulong Last = first;
        public long Packets, Bytes;
    }
    sealed class Pending(PathDeliveryReport report, byte[] query, long now)
    {
        public readonly PathDeliveryReport Report = report;
        public readonly byte[] Query = query;
        public readonly long Created = now;
        public long LastSent;
        public int Sends;
    }
    sealed class Incoming(byte[] query, long now)
    {
        public readonly byte[] Query = query;
        public readonly long Created = now;
        public byte[]? Reply;
        public bool PendingSend = true;
        public long LastSent;
        public int Sends;
    }
    public PathDeliveryFeedback(TraversalAttemptContext context)
    {
        byte[] digest = PathNomination.ContextDigest(context);
        scope = SHA256.HashData(digest.Concat("streamlink-delivery-feedback-v1"u8.ToArray()).ToArray());
    }
    static Guid Id(ReadOnlySpan<byte> p, int at) => new(p.Slice(at,16));
    static ulong Sequence(ReadOnlySpan<byte> p, int at) => BinaryPrimitives.ReadUInt64BigEndian(p[at..]);
    static long Count(ReadOnlySpan<byte> p, int at) => BinaryPrimitives.ReadInt64BigEndian(p[at..]);
    static bool Shape(ReadOnlySpan<byte> p)
    {
        if(p.Length!=FrameSize||!p[..4].SequenceEqual("SLD1"u8)||p[4]!=1||p[5] is not(1 or 2)||p[7]!=0||
            p[112..].IndexOfAnyExcept((byte)0)>=0||Id(p,40)==Guid.Empty||Id(p,56)==Guid.Empty)return false;
        ulong first=Sequence(p,72),last=Sequence(p,80);long packets=Count(p,88),bytes=Count(p,96);
        int duration=BinaryPrimitives.ReadInt32BigEndian(p[104..]),settle=BinaryPrimitives.ReadInt32BigEndian(p[108..]);
        return first>0&&last>=first&&last-first<=1_000_000&&packets is >=0 and <=100000&&bytes>=0&&bytes<=packets*MeshLink.Mtu&&
            duration is >=1 and <=30000&&(p[5]==1?p[6]==0&&packets>0&&packets<=(long)(last-first+1)&&bytes>=packets*20&&settle==0:
                p[6] is 1 or 2&&settle is >=SettleMs and <=DeadlineMs&&bytes>=packets*20);
    }
    void Store(PathDeliveryReport report){reports.Enqueue(report);while(reports.Count>3)reports.Dequeue();}
    public void Send(Guid epoch,ulong sequence,int bytes,long now)
    {
        if(sendEpoch!=epoch){sendEpoch=epoch;pending.Clear();reports.Clear();completed.Clear();current=null;}
        current??=new(epoch,sequence,now);current.Last=sequence;current.Packets++;current.Bytes+=bytes;
    }
    public void Receive(Guid epoch,ulong sequence,int bytes)
    {
        if(receiveEpoch!=epoch){receiveEpoch=epoch;receiveCursor=receiveCount=0;receiveLowWater=highestReceived=0;incoming.Clear();}
        highestReceived=Math.Max(highestReceived,sequence);
        if(receiveCount==HistorySize)receiveLowWater=Math.Max(receiveLowWater,received[receiveCursor].Sequence);
        else receiveCount++;
        received[receiveCursor]=(sequence,bytes);receiveCursor=(receiveCursor+1)%HistorySize;
    }
    byte[] Query(Guid id,Segment segment,int duration)
    {
        var p=new byte[FrameSize];"SLD1"u8.CopyTo(p);p[4]=1;p[5]=1;scope.CopyTo(p,8);id.TryWriteBytes(p.AsSpan(40));segment.Epoch.TryWriteBytes(p.AsSpan(56));
        BinaryPrimitives.WriteUInt64BigEndian(p.AsSpan(72),segment.First);BinaryPrimitives.WriteUInt64BigEndian(p.AsSpan(80),segment.Last);
        BinaryPrimitives.WriteInt64BigEndian(p.AsSpan(88),segment.Packets);BinaryPrimitives.WriteInt64BigEndian(p.AsSpan(96),segment.Bytes);
        BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(104),duration);return p;
    }
    public bool Control(ReadOnlySpan<byte> p,Guid authenticatedSenderEpoch,long now)
    {
        if(!p.StartsWith("SLD1"u8))return false;
        if(!Shape(p)||!CryptographicOperations.FixedTimeEquals(p.Slice(8,32),scope)){invalid++;return true;}
        Guid id=Id(p,40),epoch=Id(p,56);
        if(p[5]==1){
            if(epoch!=authenticatedSenderEpoch){invalid++;return true;}
            if(receiveEpoch==null)receiveEpoch=epoch;
            if(receiveEpoch!=epoch){receiveEpoch=epoch;receiveCursor=receiveCount=0;receiveLowWater=highestReceived=0;incoming.Clear();}
            if(incoming.TryGetValue(id,out var old)){
                if(!p.SequenceEqual(old.Query))invalid++;else if(old.Reply!=null&&old.Sends<3)old.PendingSend=true;
                return true;
            }
            // Completed replies remain for idempotent retry; never evict a live
            // request to satisfy untrusted new allocation pressure.
            foreach(var stale in incoming.Where(v=>now-v.Value.Created>DeadlineMs).Select(v=>v.Key).ToArray())incoming.Remove(stale);
            if(incoming.Count>=8||incoming.Values.Count(r=>r.Reply==null)>=4){deferred++;return true;}
            incoming.Add(id,new(p.ToArray(),now));return true;
        }
        if(completed.TryGetValue(id,out var prior)&&now-prior.At<=DeadlineMs&&
            CryptographicOperations.FixedTimeEquals(prior.Digest,SHA256.HashData(p)))return true;
        if(!pending.TryGetValue(id,out var expected)||epoch!=sendEpoch||epoch!=expected.Report.SendEpoch||now-expected.Created>DeadlineMs||
            Sequence(p,72)!=expected.Report.FirstSequence||Sequence(p,80)!=expected.Report.LastSequence||
            BinaryPrimitives.ReadInt32BigEndian(p[104..])!=expected.Report.EndedMs-expected.Report.StartedMs||
            Count(p,88)>expected.Report.AcceptedPackets||Count(p,96)>expected.Report.AcceptedBytes){invalid++;return true;}
        Store(expected.Report with{PeerDeliveredPackets=p[6]==1?Count(p,88):null,PeerDeliveredBytes=p[6]==1?Count(p,96):null,
            ReceiverSettleMs=BinaryPrimitives.ReadInt32BigEndian(p[108..]),Result=p[6]==1?"ReportedAtCutoff":"ReceiverHistoryIncomplete"});pending.Remove(id);
        if(completed.Count>=8)completed.Remove(completed.MinBy(p=>p.Value.At).Key);
        completed[id]=(SHA256.HashData(p),now);return true;
    }
    byte[] Reply(Incoming request,long now)
    {
        var p=request.Query.ToArray();p[5]=2;
        ulong first=Sequence(p,72),last=Sequence(p,80);long packets=0,bytes=0;
        bool complete=Id(p,56)==receiveEpoch&&first>receiveLowWater;
        if(complete)for(int i=0;i<receiveCount;i++){var item=received[i];if(item.Sequence>=first&&item.Sequence<=last){packets++;bytes+=item.Bytes;}}
        p[6]=(byte)(complete?1:2);BinaryPrimitives.WriteInt64BigEndian(p.AsSpan(88),packets);BinaryPrimitives.WriteInt64BigEndian(p.AsSpan(96),bytes);
        BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(108),(int)Math.Clamp(now-request.Created,SettleMs,DeadlineMs));return p;
    }
    public void Tick(long now,Func<byte[],bool> send)
    {
        foreach(var expired in pending.Where(p=>now-p.Value.Created>=DeadlineMs).Select(p=>p.Key).ToArray()){
            Store(pending[expired].Report with{Result="FeedbackTimeout"});pending.Remove(expired);
        }
        foreach(var old in incoming.Where(p=>now-p.Value.Created>DeadlineMs).Select(p=>p.Key).ToArray())incoming.Remove(old);
        if(current!=null&&now-current.Started>=IntervalMs&&pending.Count<2){
            var segment=current;current=null;int duration=(int)Math.Clamp(now-segment.Started,1,30000);Guid id=Guid.NewGuid();
            var report=new PathDeliveryReport(id,segment.Epoch,segment.First,segment.Last,segment.Started,segment.Started+duration,
                segment.Packets,segment.Bytes,null,null,0,"Waiting");
            byte[] query=Query(id,segment,duration);
            if(now-segment.Started>IntervalMs+500)Store(report with{Result="ObservationDiscontinuous"});
            else if(!Shape(query))Store(report with{Result="ObservationBoundsExceeded"});else pending.Add(id,new(report,query,now));
        }
        // Reports first, then queries, all through the same low-cost device
        // scheduler and actual maintenance admission supplied by the Router.
        foreach(var request in incoming.Values){
            if(now-request.Created<SettleMs||!request.PendingSend||request.Sends>=3||request.Sends>0&&now-request.LastSent<500)continue;
            request.Reply??=Reply(request,now);
            if(send(request.Reply)){request.Sends++;request.LastSent=now;request.PendingSend=false;sentControls++;}else deferred++;
        }
        foreach(var request in pending.Values){
            if(request.Sends>=3||request.Sends>0&&now-request.LastSent<2000)continue;
            if(send(request.Query)){request.Sends++;request.LastSent=now;sentControls++;}else deferred++;
        }
    }
    public void Reset(){pending.Clear();incoming.Clear();reports.Clear();completed.Clear();current=null;receiveCount=receiveCursor=0;receiveLowWater=highestReceived;}
    public PathDeliverySnapshot Snapshot()=>new(reports.ToArray(),pending.Count,incoming.Count,receiveCount,deferred,invalid,sentControls);
}
