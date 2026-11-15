using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.Discovery;

public sealed partial class MeshRegistry
{
    sealed record AssistMember(MimicAssistRequest Request,long Seen,int Generation);
    sealed class AssistPair
    {public readonly Dictionary<int,AssistMember> Members=[];public readonly HashSet<Guid> Seen=[];public readonly Queue<Guid> Order=[];public Guid Round;public long Start,LastSeen;public int Generation;}
    readonly Dictionary<string,AssistPair> assistPairs=[];
    public IResult MimicAssist(HttpContext context,string network,MimicAssistRequest request)
    {
        if(request==null||context.Connection.RemoteIpAddress is not {} source)return Results.BadRequest();
        lock(gate){
            if(!networks.TryGetValue(network,out var registration))return Results.StatusCode(412);
            if(!Equal(Auth(context),registration.AuthHash))return Results.Unauthorized();
            if(registration.Directory.Pairwise!=true||registration.Directory.Members.Length!=2)return Results.Conflict();
            var member=registration.Directory.Members.FirstOrDefault(m=>m.Slot==request.Slot&&m.Device==request.Device);
            if(member==null)return Results.StatusCode(403);
            try{PunchAssistProtocol.Verify(network,member,request);if(!PunchAssistProtocol.MatchesSource(request.Endpoint,source))return Results.Conflict();}
            catch(CryptographicException){return Results.StatusCode(403);}
            catch(FormatException){return Results.BadRequest();}
            if(!TakeRequest(network,member.Slot))return Results.StatusCode(429);
            long now=Environment.TickCount64;
            foreach(string key in assistPairs.Where(p=>now-p.Value.LastSeen>=30000).Select(p=>p.Key).ToArray())assistPairs.Remove(key);
            if(!assistPairs.TryGetValue(network,out var pair)){
                if(assistPairs.Count>=PunchAssistProtocol.MaximumSessions)return Results.StatusCode(503);
                assistPairs[network]=pair=new();
            }
            if(!pair.Seen.Add(request.RequestId))return Results.Conflict();
            pair.Order.Enqueue(request.RequestId);while(pair.Order.Count>64)pair.Seen.Remove(pair.Order.Dequeue());
            bool changed=true;
            if(pair.Members.TryGetValue(member.Slot,out var prior)){
                if(prior.Request.RequestId==request.RequestId||prior.Request.Boot==request.Boot&&prior.Request.Issued>request.Issued)return Results.Conflict();
                changed=prior.Request.Device!=request.Device||prior.Request.Boot!=request.Boot||prior.Request.Endpoint!=request.Endpoint||prior.Request.Mode!=request.Mode||prior.Request.Ready&&!request.Ready;
            }
            if(changed){pair.Round=Guid.Empty;pair.Generation++;}
            // A replaced member cannot inherit its predecessor's candidate.
            foreach(int slot in pair.Members.Keys.ToArray())if(!registration.Directory.Members.Any(m=>m.Slot==slot&&m.Device==pair.Members[slot].Request.Device))pair.Members.Remove(slot);
            pair.LastSeen=now;pair.Members[member.Slot]=new(request,now,pair.Generation);
            // After either source/boot changes, BOTH participants must report
            // in the new generation before an actionable round can exist.
            var peer=pair.Members.Values.FirstOrDefault(p=>p.Request.Slot!=member.Slot&&now-p.Seen<=10000);
            if(peer==null)return Results.Json(new MimicAssistState(1,"",Guid.Empty,0,request.Mode));
            if(peer.Request.Mode!=request.Mode)return Results.Conflict();
            if(peer.Generation!=pair.Generation||!request.Ready||!peer.Request.Ready)return Results.Json(new MimicAssistState(1,peer.Request.Endpoint,Guid.Empty,0,request.Mode));
            if(pair.Round==Guid.Empty||now-pair.Start>=10000){pair.Round=Guid.NewGuid();pair.Start=now;}
            clients?.Observe(member.Device,"",network,"自主打洞辅助");
            return Results.Json(new MimicAssistState(1,peer.Request.Endpoint,pair.Round,Math.Max(-30000,PunchAssistProtocol.MemberStartDelayMs-(int)(now-pair.Start)),request.Mode));
        }
    }
}
