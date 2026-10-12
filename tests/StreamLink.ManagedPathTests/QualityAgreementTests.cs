using System.Security.Cryptography;
using StreamLink.Core;

static class QualityAgreementTests
{
    public static object Run(Action<bool,string> check)
    {
        int cases=0;
        foreach(string mode in new[]{"normal","lose-first-vote","duplicates","one-sided","wrong-evidence","wrong-scope","expired","hard-failure"})
        for(int round=0;round<30;round++){
            long now=100000;Guid session=Guid.NewGuid();var scope=RandomNumberGenerator.GetBytes(32);string digest=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var a=new PathQualityAgreement(session,50,scope,digest,now);
            var b=new PathQualityAgreement(session,50,mode=="wrong-scope"?RandomNumberGenerator.GetBytes(32):scope,
                mode=="wrong-evidence"?Convert.ToHexString(RandomNumberGenerator.GetBytes(32)):digest,now);
            a.Approve(now,mode=="hard-failure");if(mode!="one-sided")b.Approve(now,false);
            bool droppedA=false,droppedB=false;int sent=0;
            for(int ms=0;ms<8500;ms+=100){long tick=now+ms;
                if(a.Tick(tick) is{}left){sent++;if(mode=="lose-first-vote"&&!droppedA)droppedA=true;else if(mode!="expired"){
                    _=b.Receive(left,tick);if(mode=="duplicates")_=b.Receive(left,tick);}}
                if(b.Tick(tick) is{}right){sent++;if(mode=="lose-first-vote"&&!droppedB)droppedB=true;else if(mode!="expired"){
                    _=a.Receive(right,tick);if(mode=="duplicates")_=a.Receive(right,tick);}}
                if(ms==2000){bool expected=mode is"normal" or"lose-first-vote" or"duplicates" or"hard-failure";
                    check(a.Authorized(tick)==expected&&b.Authorized(tick)==expected,mode+": only matching bilateral approval can authorize a common selection");
                    if(expected)check(a.BeginSelection(tick)&&b.BeginSelection(tick),"selection has its own bounded deadline and requires both approvals");
                }
            }
            check(sent<=34&&a.Tick(now+8500)==null&&b.Tick(now+8500)==null,"approval retries stop within the per-comparison packet and time budget");
            if(mode=="hard-failure")check(b.PeerHardFailure&&!a.PeerHardFailure,"hard failure request is carried only in the authenticated comparison vote");
            check(!a.Authorized(now+11000)&&!b.Authorized(now+11000),"old approval cannot revive a later selection");cases++;
        }
        var selection=new PathSelection(PathPolicy.AutoQuality,true);selection.Validate();
        check(selection.Reject(TraversalProfile.UdpDirect,TraversalProfile.FakeTcpHttpSo,true)!=null&&
            selection.Reject(TraversalProfile.UdpDirect,TraversalProfile.FakeTcpHttpSo,true,true)==null,
            "AutoQuality keeps the healthy-FakeTCP guard until actual comparison approval is supplied");
        check(new PathSelection(AllowUdpFallback:true).Reject(TraversalProfile.UdpDirect,TraversalProfile.FakeTcpHttpSo,true,true)!=null&&
            new PathSelection(PathPolicy.AutoQuality,false).Reject(TraversalProfile.UdpDirect,TraversalProfile.FakeTcpHttpSo,true,true)!=null,
            "quality authorization cannot override FakeTCP preference or missing UDP permission");
        return new{cases,mechanisms=8,scope="bounded authenticated-body approval/policy models; no network or Router selection claim"};
    }
}
