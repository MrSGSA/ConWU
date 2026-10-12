using System.Buffers.Binary;
using System.Security.Cryptography;

namespace StreamLink.Core;

internal enum PathDiagnosticStep:byte{Begin=1,Ready=2,Prepare=3,Prepared=4,Start=5,End=6,Report=7,Ack=8,Cancel=9,Done=10,Completed=11}
internal sealed record PathDiagnosticSummary(int Accepted,int Rejected,long ElapsedMicroseconds,long AdmittedPackets,long AdmittedBytes,long WireDenied,
    int RttSamples,double? LoadedRttP95,int Result);
internal sealed record PathDiagnosticMessage(PathDiagnosticStep Step,Guid Session,int Leg,int TargetMbps,
    PathDiagnosticSummary? Source=null,PathDiagnosticReceipt? Receipt=null);

internal static class PathDiagnosticControl
{
    internal const int Size=192;
    static int I(ReadOnlySpan<byte> p,int offset)=>BinaryPrimitives.ReadInt32BigEndian(p.Slice(offset,4));
    public static bool IsControl(ReadOnlySpan<byte> p)=>p.StartsWith("SQD2"u8);
    public static byte[] Encode(PathDiagnosticMessage m,ReadOnlySpan<byte> scope)
    {
        byte[] p=new byte[Size];"SQD2"u8.CopyTo(p);p[4]=1;p[5]=(byte)m.Step;p[6]=(byte)m.Leg;m.Session.TryWriteBytes(p.AsSpan(8));scope.CopyTo(p.AsSpan(24,32));
        BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(56),m.TargetMbps);BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(60),PathDiagnosticFrames.PayloadBytes);
        BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(64),5000);BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(68),PathDiagnosticPermit.SessionMs);
        BinaryPrimitives.WriteInt64BigEndian(p.AsSpan(72),PathDiagnosticPermit.MaximumBytes);
        if(m.Source is{}s){
            BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(80),s.Accepted);BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(84),s.Rejected);
            BinaryPrimitives.WriteInt64BigEndian(p.AsSpan(88),s.ElapsedMicroseconds);BinaryPrimitives.WriteInt64BigEndian(p.AsSpan(96),s.AdmittedPackets);
            BinaryPrimitives.WriteInt64BigEndian(p.AsSpan(104),s.AdmittedBytes);BinaryPrimitives.WriteInt64BigEndian(p.AsSpan(112),s.WireDenied);
            BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(120),s.RttSamples);BinaryPrimitives.WriteDoubleBigEndian(p.AsSpan(124),s.LoadedRttP95??-1);p[168]=(byte)s.Result;
        }
        if(m.Receipt is{}r){
            BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(80),r.ExpectedPackets);BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(132),r.ReceivedPackets);
            BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(136),r.Duplicates);BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(140),r.Reordered);
            BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(144),r.MaximumReorderDistance);BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(148),r.LongestAbsentRun);
            BinaryPrimitives.WriteDoubleBigEndian(p.AsSpan(152),r.RelativeArrivalP95Ms??-1);BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(160),r.RelativelyDelayedOver20Ms);
            BinaryPrimitives.WriteInt32BigEndian(p.AsSpan(164),r.ReceiverSettleMs);p[168]=(byte)(r.Result=="ReportedAtCutoff"?1:r.Result=="NoOfferedSamples"?2:3);
        }
        if(!TryParse(p,scope,m.TargetMbps,out _))throw new ArgumentException("Diagnostic control fields invalid");return p;
    }
    public static bool TryParse(ReadOnlySpan<byte> p,ReadOnlySpan<byte> scope,int target,out PathDiagnosticMessage? m)
    {
        m=null;
        if(p.Length!=Size||!IsControl(p)||p[4]!=1||p[5] is<1 or>11||p[6]>11||p[7]!=0||scope.Length!=32||
            !CryptographicOperations.FixedTimeEquals(p.Slice(24,32),scope)||new Guid(p.Slice(8,16))==Guid.Empty||target is<1 or>50||
            BinaryPrimitives.ReadInt32BigEndian(p[56..])!=target||BinaryPrimitives.ReadInt32BigEndian(p[60..])!=1280||
            BinaryPrimitives.ReadInt32BigEndian(p[64..])!=5000||BinaryPrimitives.ReadInt32BigEndian(p[68..])!=PathDiagnosticPermit.SessionMs||
            BinaryPrimitives.ReadInt64BigEndian(p[72..])!=PathDiagnosticPermit.MaximumBytes||p[169..].IndexOfAnyExcept((byte)0)>=0)return false;
        var step=(PathDiagnosticStep)p[5];PathDiagnosticSummary? source=null;PathDiagnosticReceipt? receipt=null;

        if(step==PathDiagnosticStep.End){
            double rtt=BinaryPrimitives.ReadDoubleBigEndian(p[124..]);int n=I(p,120),result=p[168];
            long elapsed=BinaryPrimitives.ReadInt64BigEndian(p[88..]),packets=BinaryPrimitives.ReadInt64BigEndian(p[96..]),bytes=BinaryPrimitives.ReadInt64BigEndian(p[104..]),denied=BinaryPrimitives.ReadInt64BigEndian(p[112..]);
            if(I(p,80) is<0 or>65536||I(p,84) is<0 or>1000000||elapsed is<0 or>8000000||packets is<0 or>65536||bytes is<0 or>100663296||
                denied is<0 or>1000000||n is<0 or>32||!double.IsFinite(rtt)||n==0&&rtt!=-1||n>0&&rtt is<0 or>12000||result is<1 or>3||p.Slice(132,36).IndexOfAnyExcept((byte)0)>=0)return false;
            source=new(I(p,80),I(p,84),elapsed,packets,bytes,denied,n,n==0?null:rtt,result);
        }else if(step==PathDiagnosticStep.Report){
            double relative=BinaryPrimitives.ReadDoubleBigEndian(p[152..]);int expected=I(p,80),received=I(p,132),result=p[168];
            if(expected is<0 or>65536||received is<0 or>65536||I(p,136) is<0 or>1000000||I(p,140)<0||I(p,140)>received||I(p,144) is<0 or>65535||
                I(p,148)<0||I(p,148)>expected||!double.IsFinite(relative)||relative<0&&relative!=-1||relative>100||I(p,160)<0||I(p,160)>received||
                I(p,164) is<1000 or>8000||result is<1 or>3||result==1&&(expected==0||received>expected)||result==2&&(expected!=0||received!=0)||
                p.Slice(84,48).IndexOfAnyExcept((byte)0)>=0)return false;
            receipt=new(new Guid(p.Slice(8,16)),p[6],expected,received,(long)received*1280,result==1?100d*(expected-received)/expected:null,
                I(p,136),I(p,140),I(p,144),I(p,148),relative<0?null:relative,I(p,160),I(p,164),result==1?"ReportedAtCutoff":result==2?"NoOfferedSamples":"InvalidSummary");
        }else if(p[80..].IndexOfAnyExcept((byte)0)>=0)return false;
        m=new(step,new Guid(p.Slice(8,16)),p[6],target,source,receipt);return true;
    }
}
