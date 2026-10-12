using System.Buffers.Binary;

namespace StreamLink.Core;

internal static class PathDiagnosticFrames
{
    internal const int PayloadBytes=1280,MaximumSamples=65536;
    public static byte[] Encode(Guid session,int leg,int sample,int elapsedMs)
    {
        if(session==Guid.Empty||leg is<0 or>11||sample is<0 or>=MaximumSamples||elapsedMs is<0 or>15000)throw new ArgumentException("Invalid diagnostic sample");
        byte[] payload=new byte[PayloadBytes];"SLQ1"u8.CopyTo(payload);payload[4]=1;payload[5]=(byte)leg;
        session.TryWriteBytes(payload.AsSpan(8));BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(24),sample);
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(28),elapsedMs);return payload;
    }
    public static bool Parse(ReadOnlySpan<byte> payload,Guid session,int leg,out int sample,out int elapsedMs)
    {
        sample=elapsedMs=0;
        if(payload.Length!=PayloadBytes||!payload[..4].SequenceEqual("SLQ1"u8)||payload[4]!=1||payload[5]!=leg||payload[6]!=0||payload[7]!=0||
            session==Guid.Empty||new Guid(payload.Slice(8,16))!=session||payload[32..].IndexOfAnyExcept((byte)0)>=0)return false;
        sample=BinaryPrimitives.ReadInt32BigEndian(payload[24..]);elapsedMs=BinaryPrimitives.ReadInt32BigEndian(payload[28..]);
        return sample is>=0 and<MaximumSamples&&elapsedMs is>=0 and<=15000;
    }
}

public sealed record PathDiagnosticReceipt(Guid SessionId,int Leg,int ExpectedPackets,int ReceivedPackets,long ReceivedPayloadBytes,
    double? DeficitAtCutoffPercent,int Duplicates,int Reordered,int MaximumReorderDistance,int LongestAbsentRun,
    double? RelativeArrivalP95Ms,int RelativelyDelayedOver20Ms,int ReceiverSettleMs,string Result)
{
    public string Scope=>"Authenticated diagnostic ingress at receipt cutoff; relative arrival delay is measured against the first sample, not absolute one-way latency or application delivery";
}

// Allocated only after an authenticated, explicitly allowed measurement request.
// The sole Router receiver records the exact path/session/leg, then one bounded
// cutoff seals the report. Late packets cannot improve an already sealed result.
internal sealed class PathDiagnosticReceiver(Guid session,int leg,TimeProvider? clock=null)
{
    readonly TimeProvider time=clock??TimeProvider.System;
    readonly byte[] seen=new byte[PathDiagnosticFrames.MaximumSamples/8];
    readonly int[] arrival=new int[9];
    static readonly double[] limits=[0,1,2,5,10,20,50,100,double.PositiveInfinity];
    int received,duplicates,reordered,maximumDistance,highest=-1,firstTransmit,late;
    long firstReceive;
    bool started;
    PathDiagnosticReceipt? final;
    public bool Record(ReadOnlySpan<byte> payload)
    {
        if(final!=null||!PathDiagnosticFrames.Parse(payload,session,leg,out int sample,out int elapsedMs))return false;
        int at=sample/8,mask=1<<(sample%8);if((seen[at]&mask)!=0){duplicates++;return false;}seen[at]|=(byte)mask;
        if(sample<highest){reordered++;maximumDistance=Math.Max(maximumDistance,highest-sample);}highest=Math.Max(highest,sample);
        if(!started){started=true;firstReceive=time.GetTimestamp();firstTransmit=elapsedMs;}
        double delay=time.GetElapsedTime(firstReceive).TotalMilliseconds-(elapsedMs-firstTransmit);
        if(delay>20)late++;int bucket=Array.FindIndex(limits,limit=>delay<=limit);arrival[bucket<0?arrival.Length-1:bucket]++;
        received++;return true;
    }
    public PathDiagnosticReceipt Finish(int expectedPackets,int receiverSettleMs)
    {
        if(final!=null)return final;
        if(expectedPackets is<0 or>PathDiagnosticFrames.MaximumSamples||receiverSettleMs is<1000 or>8000)throw new ArgumentException("Invalid diagnostic cutoff summary");
        string result=received>expectedPackets||highest>=expectedPackets?"InvalidSummary":expectedPackets==0?"NoOfferedSamples":"ReportedAtCutoff";
        int longest=0,run=0;for(int i=0;i<expectedPackets;i++){
            if((seen[i/8]&(1<<(i%8)))==0){run++;longest=Math.Max(longest,run);}else run=0;
        }
        double? p95=null;if(received>0){int target=(int)Math.Ceiling(received*.95),sum=0;
            for(int i=0;i<arrival.Length;i++){sum+=arrival[i];if(sum>=target){p95=double.IsFinite(limits[i])?limits[i]:null;break;}}}
        return final=new(session,leg,expectedPackets,received,(long)received*PathDiagnosticFrames.PayloadBytes,
            result=="ReportedAtCutoff"?100d*(expectedPackets-received)/expectedPackets:null,duplicates,reordered,maximumDistance,longest,p95,late,receiverSettleMs,result);
    }
}
