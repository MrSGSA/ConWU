using StreamLink.Core;
using System.Text.Json;

static class QualityAssessmentTests
{
    public static object Replay(string file)
    {
        using var doc=JsonDocument.Parse(File.ReadAllText(file));var output=new List<object>();
        foreach(var row in doc.RootElement.GetProperty("rows").EnumerateArray())
        foreach(var element in row.GetProperty("diagnostics").EnumerateArray()){
            var status=element.Deserialize<PathDiagnosticSessionStatus>()!;
            ValidatedPathIdentity From(int leg){var w=status.Windows.Single(w=>w.Leg==leg);return new(w.PathId,Guid.NewGuid(),w.ResourceId,null,w.NetworkGeneration,
                new(System.Net.IPAddress.Loopback,40001),new(System.Net.IPAddress.Loopback,40002),TraversalProfile.UdpDirect,PathQualification.MtuQualified);}
            output.Add(PathQualityEvaluator.Assess(status,From(0),From(3),status.Windows.Max(w=>w.ObservedMs)+100));
        }
        return new{scope="offline rule analysis of previously recorded reports at reconstructed local time; not a new network or selection result",output};
    }
    public static object Run(Action<bool,string> check)
    {
        Guid id=Guid.NewGuid();var active=Identity();var candidate=Identity();const long now=100000;
        PathDiagnosticWindow Window(int leg,bool badActive=false){var path=leg%6<3?active:candidate;bool bad=badActive&&leg<3;
            int accepted=25000,received=bad?3000:accepted;
            return new(id,leg,leg<6?1:2,path.PathId,path.LeaseId,path.NetworkGeneration,50,
                new(accepted,0,5000,accepted,accepted*1450L,0,4,12,"Completed"),
                new(id,leg,accepted,received,received*1280L,100d*(accepted-received)/accepted,0,0,0,accepted-received,2,0,1000,"ReportedAtCutoff"),now-1000);}
        PathDiagnosticSessionStatus Status(bool badActive=false)=>new(id,"Done",11,50,"",new(id,0,0,0,80000,false),Enumerable.Range(0,12).Select(i=>Window(i,badActive)).ToArray());
        var good=Status();var assessment=PathQualityEvaluator.Assess(good,active,candidate,now);
        check(assessment is{CandidateQualified:true,StableBenefit:false,Reason:"RetainHealthyActiveNoStableBenefit"},"equally qualified diagnostic paths do not cause automatic churn");
        var bad=Status(true);check(PathQualityEvaluator.Assess(bad,active,candidate,now) is{CandidateQualified:true,StableBenefit:true},
            "three consistently improved upload windows qualify a candidate without hiding healthy opposite direction");
        foreach(string mode in new[]{"active-stale","active-local-reject"}){
            var rows=good.Windows.ToArray();rows[0]=mode=="active-stale"?rows[0] with{ObservedMs=now-90001}:rows[0] with{Source=rows[0].Source with{WireDenied=1}};
            check(PathQualityEvaluator.Assess(good with{Windows=rows},active,candidate,now) is{CandidateQualified:true,StableBenefit:false},
                mode+": fresh candidate stays eligible only for genuine hard recovery, never a normal quality switch");
        }
        foreach(string mode in new[]{"idle-rtt-only","stale","different-resource","local-drop","missing-rtt","inconsistent-count","one-good-window","bad-candidate","direction-tradeoff"}){
            var rows=bad.Windows.ToArray();int index=3;var row=rows[index];
            rows[index]=mode switch{
                "stale"=>row with{ObservedMs=now-90001},"different-resource"=>row with{ResourceId=Guid.NewGuid()},
                "local-drop"=>row with{Source=row.Source with{WireDenied=1}},"missing-rtt"=>row with{Source=row.Source with{LoadedRttSamples=0,LoadedRttP95Ms=null}},
                "inconsistent-count"=>row with{Receipt=row.Receipt with{DeficitAtCutoffPercent=.05}},
                "bad-candidate"=>row with{Receipt=row.Receipt with{ReceivedPackets=10000,ReceivedPayloadBytes=12800000,DeficitAtCutoffPercent=60}},
                _=>row};
            if(mode=="idle-rtt-only")rows=[];
            if(mode=="one-good-window"){rows[1]=Window(1);rows[2]=Window(2);}
            if(mode=="direction-tradeoff")for(int n=9;n<12;n++)rows[n]=rows[n] with{Source=rows[n].Source with{LoadedRttP95Ms=40}};
            var result=PathQualityEvaluator.Assess(bad with{Windows=rows},active,candidate,now);
            check(!result.StableBenefit,mode+": no selection benefit can bypass required matched direction/identity/load evidence");
        }
        var other=bad with{Windows=bad.Windows.Select(w=>w with{PathId=Guid.NewGuid(),ResourceId=Guid.NewGuid(),ObservedMs=now-100}).ToArray()};
        check(PathQualityEvaluator.Digest(bad)==PathQualityEvaluator.Digest(other),"comparison vote digest agrees across machines with different local identities and clocks");
        check(PathQualityEvaluator.Assess(bad,active,Identity(),now).Result=="QualityUnknown","new actual candidate cannot inherit old resource qualification");
        return new{scope="quality rule/digest models; synthetic diagnostic evidence, no actual policy switch or network"};
    }
    static ValidatedPathIdentity Identity()=>new(Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),null,Guid.NewGuid(),
        new(System.Net.IPAddress.Loopback,40001),new(System.Net.IPAddress.Loopback,40002),TraversalProfile.UdpDirect,PathQualification.MtuQualified);
}
