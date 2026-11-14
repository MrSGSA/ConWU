using StreamLink.Core;

namespace StreamLink.Discovery;
public sealed partial class MeshRegistry
{
    readonly Dictionary<string,EntryLookupRecord> entryCodes=new(StringComparer.Ordinal);
    void PruneEntryCodes()
    {
        long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        foreach(var code in entryCodes.Where(p=>p.Value.Entry.Expires<=now||!networks.TryGetValue(p.Value.Entry.Network,out var n)||n.Directory.Closed||!n.Directory.Members.Contains(p.Value.Host)).Select(p=>p.Key).ToArray())entryCodes.Remove(code);
    }
    public IResult PublishEntry(HttpContext context,string network,EntryAdvertisement entry)
    {
        lock(gate){
            if(!networks.TryGetValue(network,out var registration))return Results.NotFound();
            if(!Equal(Auth(context),registration.AuthHash))return Results.Unauthorized();
            if(registration.Directory.Closed)return Results.StatusCode(403);
            var host=registration.Directory.Members.FirstOrDefault(m=>m.Slot==1);
            if(host==null||entry==null||entry.Network!=network)return Results.BadRequest();
            var record=new EntryLookupRecord(registration.Directory.OwnerKey,host,entry);
            try{EntryLookup.Validate(record,entry.Code);}catch{return Results.BadRequest();}
            if(!TakeRequest(network,1))return Results.StatusCode(429);
            PruneEntryCodes();
            if(entryCodes.TryGetValue(entry.Code,out var prior)&&prior.Entry.Network!=network)return Results.Conflict();
            if(entryCodes.Count>=512&&!entryCodes.ContainsKey(entry.Code))return Results.StatusCode(503);
            // A new room invalidates the previous room's code immediately.
            foreach(var old in entryCodes.Where(p=>p.Value.Entry.Network==network&&p.Key!=entry.Code).Select(p=>p.Key).ToArray())entryCodes.Remove(old);
            entryCodes[entry.Code]=record;return Results.NoContent();
        }
    }
    public IResult FindEntry(EntryLookupQuery query)
    {
        if(!EntryLookup.ValidCode(query?.Code))return Results.BadRequest();
        lock(gate){PruneEntryCodes();return entryCodes.TryGetValue(query!.Code,out var found)?Results.Json(found):Results.NotFound();}
    }
}
