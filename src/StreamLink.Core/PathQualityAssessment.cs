using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

public sealed record PathQualityAssessment(Guid SessionId,Guid ActivePathId,Guid CandidatePathId,int TargetMbps,
    bool CandidateQualified,bool StableBenefit,string Result,string Reason,long AssessedMs,string EvidenceDigest,string Profile="LegacyDiagnostic")
{
    public string Scope=>Profile=="RelativeIdleRtt"?"Three matched windows per direction, same-path idle/loaded RTT delta and authenticated ingress; application deadline and one-way latency NotMeasurable":
        "Three matched diagnostic windows per direction, authenticated ingress at cutoff and loaded round trips; not absolute one-way latency or application delivery";
}

internal static class PathQualityEvaluator
{
    static readonly JsonSerializerOptions digestOptions=new(){NumberHandling=System.Text.Json.Serialization.JsonNumberHandling.AllowNamedFloatingPointLiterals};
    public const int FreshMs=90000;
    static string? Basis(PathDiagnosticWindow w,long now,int target,Guid session,bool relative)
    {
        if(w.SessionId!=session||w.TargetMbps!=target||w.Leg is<0 or>=12||w.PathId==Guid.Empty||w.ResourceId==Guid.Empty||w.NetworkGeneration==Guid.Empty) return "ContextMismatch";
        if(now-w.ObservedMs is<0 or>FreshMs) return "ExpiredObservation";
        if(w.Source.Result!="Completed"||w.Source.ElapsedMs is<4900 or>5500||w.Source.Accepted is<=0 or>65536) return "IncompleteSourceWindow";
        if(w.Source.Rejected!=0||w.Source.WireDenied!=0) return "LocalSourceRejected";
        if(w.Source.AdmittedPackets!=w.Source.Accepted||w.Source.AdmittedBytes<w.Source.Accepted*1372L||w.Source.AdmittedBytes>w.Source.Accepted*1536L) return "SourceAccountingMismatch";
        if(w.Receipt.SessionId!=session||w.Receipt.Leg!=w.Leg||w.Receipt.ExpectedPackets!=w.Source.Accepted||
            w.Receipt.ReceivedPackets<0||w.Receipt.ReceivedPackets>w.Source.Accepted||w.Receipt.DeficitAtCutoffPercent is not{}deficit||!double.IsFinite(deficit)||
            Math.Abs(deficit-100d*(w.Source.Accepted-w.Receipt.ReceivedPackets)/w.Source.Accepted)>.000001) return "ReceiptCountMismatch";
        if(w.Receipt.Result!="ReportedAtCutoff"||w.Receipt.ReceiverSettleMs is<1000 or>8000) return "IncompleteReceipt";
        if(w.Source.LoadedRttSamples is<2 or>32||w.Source.LoadedRttP95Ms is not{}rtt||!double.IsFinite(rtt)||rtt<0||
            w.Receipt.RelativeArrivalP95Ms is not{}arrival||!double.IsFinite(arrival)||arrival<0) return "MissingLoadedTiming";
        if(relative&&(w.Source.IdleRttSamples is<4 or>8||w.Source.IdleRttP95Ms is not{}idle||!double.IsFinite(idle)||idle is<0 or>12000||w.Source.IdleAgeMs is<0 or>=30000))return "MissingOrStaleIdleTiming";
        return null;
    }
    static double Rate(PathDiagnosticWindow w)=>w.Receipt.ReceivedPayloadBytes*8d/w.Source.ElapsedMs/1000;
    static bool Qualified(PathDiagnosticWindow w,int target,bool relative)=>Rate(w)>=target*(relative?.98:1)&&w.Receipt.DeficitAtCutoffPercent is>=0 and<=.1&&
        (relative?w.Source.LoadedRttP95Ms-w.Source.IdleRttP95Ms<=20:w.Source.LoadedRttP95Ms<=50)&&w.Receipt.RelativeArrivalP95Ms<=20;
    static bool Better(PathDiagnosticWindow a,PathDiagnosticWindow b,int target,bool relative)=>Qualified(b,target,relative)&&
        (!Qualified(a,target,relative)||b.Source.LoadedRttP95Ms<=a.Source.LoadedRttP95Ms-Math.Max(5,a.Source.LoadedRttP95Ms!.Value*.2)||
            b.Receipt.DeficitAtCutoffPercent<=a.Receipt.DeficitAtCutoffPercent-.05);
    static bool NoRegression(PathDiagnosticWindow a,PathDiagnosticWindow b,int target,bool relative)=>!Qualified(a,target,relative)||
        Rate(b)>=Rate(a)*.95&&b.Source.LoadedRttP95Ms<=Math.Max(a.Source.LoadedRttP95Ms!.Value+5,a.Source.LoadedRttP95Ms.Value*1.2)&&
        b.Receipt.DeficitAtCutoffPercent<=a.Receipt.DeficitAtCutoffPercent+.05;
    public static string Digest(PathDiagnosticSessionStatus status){var basis=JsonSerializer.SerializeToUtf8Bytes(new{
        domain="streamlink-quality-comparison-v1",status.SessionId,status.TargetMbps,
        windows=status.Windows.OrderBy(w=>w.Leg).Select(w=>new{w.Leg,w.SourceSlot,w.TargetMbps,w.Source,w.Receipt})},digestOptions);
        return Convert.ToHexString(SHA256.HashData(status.TimingVersion==0?basis:JsonSerializer.SerializeToUtf8Bytes(new{domain="streamlink-quality-comparison-v2",status.TimingVersion,basis})));}
    public static PathQualityAssessment Assess(PathDiagnosticSessionStatus status,ValidatedPathIdentity active,ValidatedPathIdentity candidate,long now)
    {
        string digest=Digest(status);
        bool relative=status.TimingVersion==1;
        PathQualityAssessment Result(bool qualified,bool gain,string result,string reason)=>new(status.SessionId,active.PathId,candidate.PathId,status.TargetMbps,qualified,gain,result,reason,now,digest,relative?"RelativeIdleRtt":"LegacyDiagnostic");
        if(status.TimingVersion is<0 or>1||status.State!="Done"||status.Windows.Length!=12||status.Windows.Select(w=>w.Leg).Distinct().Count()!=12||status.TargetMbps is<1 or>50)
            return Result(false,false,"QualityUnknown","IncompleteComparison");
        var windows=status.Windows.OrderBy(w=>w.Leg).ToArray();
        string? activeUnavailable=null;
        for(int i=0;i<12;i++){
            var w=windows[i];var identity=i%6<3?active:candidate;
            if(w.Leg!=i||w.PathId!=identity.PathId||w.ResourceId!=identity.LeaseId||w.NetworkGeneration!=identity.NetworkGeneration||
                w.Receipt.ReceivedPayloadBytes!=(long)w.Receipt.ReceivedPackets*1280)
                return Result(false,false,"QualityUnknown","ResourceOrPayloadMismatch:"+i);
            if(Basis(w,now,status.TargetMbps,status.SessionId,relative) is{}problem){
                if(i%6>=3)return Result(false,false,"QualityUnknown",problem+":"+i);
                activeUnavailable??=problem+":"+i;
            }
        }
        if(windows.Take(6).Select(w=>w.SourceSlot).Distinct().Count()!=1||windows.Skip(6).Select(w=>w.SourceSlot).Distinct().Count()!=1||windows[0].SourceSlot==windows[6].SourceSlot)
            return Result(false,false,"QualityUnknown","DirectionMismatch");
        if(relative)foreach(int start in new[]{0,3,6,9}){
            var baseline=windows[start].Source;
            if(Enumerable.Range(start,3).Any(i=>windows[i].Source.IdleRttSamples!=baseline.IdleRttSamples||windows[i].Source.IdleRttP95Ms!=baseline.IdleRttP95Ms)||
                windows[start+1].Source.IdleAgeMs<windows[start].Source.IdleAgeMs||windows[start+2].Source.IdleAgeMs<windows[start+1].Source.IdleAgeMs)
                return Result(false,false,"QualityUnknown","IdleBaselineGroupMismatch");
        }
        bool candidateGood=windows.Where(w=>w.Leg%6>=3).All(w=>Qualified(w,status.TargetMbps,relative));
        if(!candidateGood)return Result(false,false,"QualityInsufficient","CandidateDoesNotMeetDiagnosticTarget");
        // Candidate qualification and normal comparison are different facts.
        // A stale/locally rejected Active window cannot justify a normal
        // quality switch. It also cannot erase fresh candidate evidence needed
        // when the worker genuinely exits or Active becomes a black hole.
        if(activeUnavailable!=null)return Result(true,false,"QualityObservedDiagnostic","ActiveEvidenceUnavailable:"+activeUnavailable);
        if(new[]{0,6}.Any(start=>Enumerable.Range(start,3).Any(i=>!NoRegression(windows[i],windows[i+3],status.TargetMbps,relative))))
            return Result(true,false,"QualityObservedDiagnostic","RetainActiveDirectionalTradeoff");
        bool gain=false;
        foreach(int start in new[]{0,6}){
            if(Enumerable.Range(start,3).All(i=>Better(windows[i],windows[i+3],status.TargetMbps,relative)))gain=true;
        }
        return Result(true,gain,"QualityObservedDiagnostic",gain?"ThreeWindowBenefit":"RetainHealthyActiveNoStableBenefit");
    }
}
