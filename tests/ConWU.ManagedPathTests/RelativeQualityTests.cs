using StreamLink.Core;
using System.Net;

static class RelativeQualityTests
{
    public static object Run(Action<bool,string> check)
    {
        Guid session=Guid.NewGuid();const long now=100000;
        ValidatedPathIdentity Identity()=>new(Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),null,Guid.NewGuid(),new(IPAddress.Loopback,40001),new(IPAddress.Loopback,40002),TraversalProfile.FakeTcpHttpSo,PathQualification.MtuQualified);
        var active=Identity();var candidate=Identity();
        PathDiagnosticWindow Window(int leg){var path=leg%6<3?active:candidate;const int accepted=24000;
            return new(session,leg,leg<6?1:2,path.PathId,path.LeaseId,path.NetworkGeneration,50,
                new(accepted,0,5000,accepted,accepted*1450L,0,4,120,"Completed",4,100,7000+leg%3*7000),
                new(session,leg,accepted,accepted,accepted*1280L,0,0,0,0,0,2,0,1000,"ReportedAtCutoff"),now-1000);}
        var status=new PathDiagnosticSessionStatus(session,"Done",11,50,"",new(session,0,0,0,80000,false),Enumerable.Range(0,12).Select(Window).ToArray(),1);
        var result=PathQualityEvaluator.Assess(status,active,candidate,now);
        check(result.CandidateQualified&&!result.StableBenefit&&result.Profile=="RelativeIdleRtt","high baseline RTT with exactly 20ms loaded increase and 49.152Mbps qualifies the standard relative profile");
        check(!PathQualityEvaluator.Assess(status with{TimingVersion=0},active,candidate,now).CandidateQualified,"legacy profile remains conservative and does not infer relative permission from appended values");
        PathDiagnosticSessionStatus Changed(Func<PathDiagnosticWindow,PathDiagnosticWindow> alter)=>status with{Windows=status.Windows.Select(alter).ToArray()};
        foreach(string condition in new[]{"delta","throughput","missing","stale","nonfinite","group","age-order"}){
            var changed=Changed(w=>w.Leg%6<3?w:w with{Source=condition switch{
                "delta"=>w.Source with{LoadedRttP95Ms=120.01},
                "throughput"=>w.Source with{Accepted=23900,AdmittedPackets=23900,AdmittedBytes=23900*1450L},
                "missing"=>w.Source with{IdleRttSamples=0,IdleRttP95Ms=null},
                "stale"=>w.Source with{IdleAgeMs=30000},
                "nonfinite"=>w.Source with{IdleRttP95Ms=double.NaN},
                "group"=>w.Source with{IdleRttP95Ms=w.Leg%3==1?101:100},
                _=>w.Source with{IdleAgeMs=21000-w.Leg%3*7000}
            }});
            if(condition=="throughput")changed=changed with{Windows=changed.Windows.Select(w=>w.Leg%6<3?w:w with{Receipt=w.Receipt with{ExpectedPackets=23900,ReceivedPackets=23900,ReceivedPayloadBytes=23900*1280L}}).ToArray()};
            check(!PathQualityEvaluator.Assess(changed,active,candidate,now).CandidateQualified,"relative qualification rejects "+condition+" without fallback to absolute or idle-only selection");
        }
        check(PathQualityEvaluator.Digest(status)!=PathQualityEvaluator.Digest(status with{TimingVersion=0}),"quality approval digests bind the negotiated timing profile");
        byte[] scope=new byte[32];var source=new PathDiagnosticSummary(100,0,5000000,100,145000,0,4,120,1,4,100,8000);
        var packet=PathDiagnosticControl.Encode(new(PathDiagnosticStep.End,session,3,50,source,TimingVersion:1),scope);
        check(PathDiagnosticControl.TryParse(packet,scope,50,out var parsed,1)&&parsed!.Source==source,"version two source report carries authenticated same-path baseline samples and age");
        check(!PathDiagnosticControl.TryParse(packet,scope,50,out _),"legacy parser rejects a timing-v2 report rather than interpreting it under v1 rules");
        var legacy=PathDiagnosticControl.Encode(new(PathDiagnosticStep.End,session,3,50,source with{IdleRttSamples=0,IdleRttP95=null,IdleAgeMs=0}),scope);
        check(!PathDiagnosticControl.TryParse(legacy,scope,50,out _,1),"a v2-negotiated session rejects a v1 source report");
        packet[172]=127;check(!PathDiagnosticControl.TryParse(packet,scope,50,out _,1),"baseline sample counts are bounded before report allocation");
        return new{scope="models and bounded report parser; no driver, WAN or throughput measurement"};
    }
}
