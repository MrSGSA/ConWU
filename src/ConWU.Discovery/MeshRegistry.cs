using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using StreamLink.Core;

namespace StreamLink.Discovery;
public sealed partial class MeshRegistry
{
    public sealed record Registration(string AuthHash, MeshDirectory Directory);
    readonly object gate = new();
    readonly string file;
    readonly Dictionary<string, Registration> networks;
    readonly Dictionary<string, (MeshEnvelope Envelope, DateTimeOffset Expires)> nodes = [];
    readonly CoordinatorClients? clients;
    public MeshRegistry(string root,CoordinatorClients? clients=null) { this.clients=clients;file = Path.Combine(root, "mesh-networks.json"); networks = CoordinationStorage.Load<Registration>(file, ValidateStored); }
    internal static void ValidateStored(string network, Registration record) {
        if(record == null || !Regex.IsMatch(record.AuthHash ?? "", "^[A-F0-9]{64}$") || record.Directory == null)
            throw new IOException("协调成员记录无效");
        MeshIdentity.ValidateDirectory(record.Directory, network, record.Directory.OwnerKey);
    }
    void Save() => CoordinationStorage.Write(file, networks);
    static string Auth(HttpContext context) { string value = context.Request.Headers.Authorization.ToString(); return Regex.IsMatch(value, "^Bearer [A-F0-9]{64}$") ? Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(value))) : ""; }
    static bool Equal(string a, string b) => a.Length == 64 && b.Length == 64 && CryptographicOperations.FixedTimeEquals(Convert.FromHexString(a), Convert.FromHexString(b));
    public IResult Directory(HttpContext context, string network, MeshDirectory directory)
    {
        string auth = Auth(context); if (auth.Length == 0) return Results.Unauthorized();
        if(directory==null)return Results.BadRequest();
        // The replication route cannot create a governed network. Reject
        // unknown/unauthorized requests before decompressing signed history.
        lock(gate){
            if(networks.TryGetValue(network,out var registered)){
                if(!Equal(auth,registered.AuthHash))return Results.Unauthorized();
            }else if(directory.Governance!=null)return Results.Conflict();
        }
        try { MeshIdentity.ValidateDirectory(directory, network, directory.OwnerKey); } catch { return Results.BadRequest(); }
        lock (gate) {
            networks.TryGetValue(network,out var known);
            if(directory.Governance!=null || known?.Directory.Governance!=null){
                if(known==null)return Results.Conflict();
                if(directory.Governance==null)return Results.Conflict();
                if(!Equal(auth,known.AuthHash))return Results.Unauthorized();
                try{MeshIdentity.ValidateSuccessor(known.Directory,directory);}catch{return Results.Conflict();}
                return Results.NoContent(); // Governance edits use the atomic membership endpoint only.
            }
            if (networks.TryGetValue(network, out var prior)) {
                if (!Equal(auth, prior.AuthHash)) return Results.Unauthorized();
                if (!TakeRequest(network, 1)) return Results.StatusCode(429);
                if (directory.OwnerKey != prior.Directory.OwnerKey || directory.Revision < prior.Directory.Revision || directory.NextSlot < prior.Directory.NextSlot) return Results.Conflict();
                if (directory.Revision == prior.Directory.Revision) return directory.Signature == prior.Directory.Signature ? Results.NoContent() : Results.Conflict();
                if (directory.Members.Any(m => m.Slot < prior.Directory.NextSlot && !prior.Directory.Members.Contains(m))) return Results.Conflict();
                try { MeshIdentity.ValidateSuccessor(directory, prior.Directory); } catch (CryptographicException) { return Results.Conflict(); }
            } else if (networks.Count >= CoordinationStorage.MaximumNetworks) return Results.Json(new { error = "coordination-network-capacity" }, statusCode: 507);
            networks[network] = new(auth, directory);
            try { Save(); }
            catch {
                if (prior != null) networks[network] = prior; else networks.Remove(network);
                throw;
            }
            foreach (var key in nodes.Keys.Where(k => k.StartsWith(network + "/", StringComparison.Ordinal)).ToArray())
                if (!directory.Members.Any(m => m.Slot == nodes[key].Envelope.Slot && m.Device == nodes[key].Envelope.Device)) nodes.Remove(key);
            Changed(network, "directory", 0);
            return Results.NoContent();
        }
    }
    public IResult Publish(HttpContext context, string network, int slot, MeshEnvelope envelope)
    {
        lock (gate) {
            if (!networks.TryGetValue(network, out var registration)) return Results.NotFound();
            if (!Equal(Auth(context), registration.AuthHash)) return Results.Unauthorized();
            var member = registration.Directory.Members.FirstOrDefault(m => m.Slot == slot); if (member == null) return Results.StatusCode(403);
            try { MeshMetadata.ValidateEnvelope(network, member, envelope); } catch { return Results.BadRequest(); }
            if (!TakeRequest(network, slot)) return Results.StatusCode(429);
            string key = network + "/" + slot;
            if (nodes.TryGetValue(key, out var old) && envelope.Revision <= old.Envelope.Revision) return Results.Conflict();
            nodes[key] = (envelope, DateTimeOffset.UtcNow.AddSeconds(120)); Changed(network, "announcement", slot);
            clients?.Observe(member.Device,"",network,"网络发现");
            return Results.NoContent();
        }
    }
    public IResult Read(HttpContext context, string network)
    {
        lock (gate) {
            if (!networks.TryGetValue(network, out var registration)) return Results.NotFound();
            if (!Equal(Auth(context), registration.AuthHash)) return Results.Unauthorized();
            var found = registration.Directory.Members.Select(m => nodes.GetValueOrDefault(network + "/" + m.Slot)).Where(n => n.Envelope != null && n.Expires > DateTimeOffset.UtcNow).Select(n => n.Envelope).ToArray();
            return Results.Json(new MeshSnapshot(registration.Directory, found));
        }
    }
}
