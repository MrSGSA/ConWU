using StreamLink.Core;

namespace StreamLink.Discovery;

public sealed partial class MeshRegistry
{
    readonly Dictionary<string,(double Tokens,long Tick)> membershipRequests=[];
    bool TakeMembershipRequest(string network)
    {
        long now=System.Diagnostics.Stopwatch.GetTimestamp();
        var old=membershipRequests.GetValueOrDefault(network,(32,now));
        double tokens=Math.Min(32,old.Item1+System.Diagnostics.Stopwatch.GetElapsedTime(old.Item2,now).TotalSeconds);
        membershipRequests[network]=(Math.Max(0,tokens-1),now);return tokens>=1;
    }
    public IResult Membership(HttpContext context,string network,MeshMembershipRequest request)
    {
        string auth=Auth(context);
        if(auth.Length==0)return Results.Unauthorized();
        if(request.ExpectedHead is not {Length:0 or 64} || request.Directory?.Governance==null)return Results.BadRequest();
        lock(gate){
            networks.TryGetValue(network,out var prior);
            if(prior!=null&&!Equal(auth,prior.AuthHash))return Results.Unauthorized();
            // Only registered/authenticated networks allocate a budget. Keep
            // management bursts independent of creator-slot watch traffic.
            if(prior!=null&&!TakeMembershipRequest(network))return Results.StatusCode(429);
            var next=request.Directory;
            try{MeshIdentity.ValidateDirectory(next,network,next.OwnerKey);}catch{return Results.BadRequest();}
            if(prior!=null){
                // An exact retransmission, or a committed ancestor, is success.
                // This handles lost replies without issuing another membership.
                try{MeshIdentity.ValidateSuccessor(prior.Directory,next);return Results.Json(prior.Directory);}catch{ }
                if(MeshGovernance.Head(prior.Directory)!=request.ExpectedHead)return Results.Conflict(prior.Directory);
                try{
                    MeshIdentity.ValidateSuccessor(next,prior.Directory);
                    // One atomic operation per compare-and-set. Migration may
                    // contain only the creator's explicit policy authorization.
                    var history=MeshGovernance.Unpack(next.Governance);
                    int before=prior.Directory.Governance==null?-1:MeshGovernance.Unpack(prior.Directory.Governance).Changes.Length;
                    if(history.Changes.Length!=before+1)return Results.Conflict(prior.Directory);
                }catch{return Results.Conflict(prior.Directory);}
            }else{
                if(request.ExpectedHead.Length!=0)return Results.NotFound();
                if(networks.Count>=2048)return Results.StatusCode(503);
                var history=MeshGovernance.Unpack(next.Governance);
                if(history.Changes.Length!=0 || history.Genesis.Revision!=1 || history.Genesis.Members.Length!=1)return Results.BadRequest();
            }
            networks[network]=new(auth,next);
            try{Save();}catch{if(prior==null)networks.Remove(network);else networks[network]=prior;throw;}
            foreach(var key in nodes.Keys.Where(k=>k.StartsWith(network+"/",StringComparison.Ordinal)).ToArray())
                if(!next.Members.Any(m=>m.Slot==nodes[key].Envelope.Slot&&m.Device==nodes[key].Envelope.Device))nodes.Remove(key);
            Changed(network,"directory",0);
            return Results.Json(next);
        }
    }
}
