using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    // Explicit, optional live test. Uses an ephemeral key and documentation-only
    // candidate addresses, never an installed identity or the user's endpoints.
    static async Task PkarrPublicTests(string output)
    {
        string seed=PkarrPacket.NewSeed(),source=PkarrPacket.Source(seed);var watch=System.Diagnostics.Stopwatch.StartNew();
        int accepted=0,updated=0;bool first=false,changed=false;string error="";
        try{
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(90));using var client=new PkarrClient();
            long sequence=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()*1000;
            var announcement=new PkarrAnnouncement(1,"faketcp",DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds(),["203.0.113.44:44680"]);
            accepted=await client.Publish(seed,PkarrPacket.Create(seed,sequence,announcement),deadline.Token);
            for(int attempt=0;attempt<4;attempt++){
                try{first=(await client.Resolve(source,"faketcp",deadline.Token)).SequenceEqual(announcement.Endpoints);}catch(IOException){}
                if(first)break;await Task.Delay(1000,deadline.Token);
            }
            Check(first,"public PKARR HTTPS gateways accept and return a verified standard signed record");
            var next=announcement with{Endpoints=["203.0.113.45:44681"]};
            updated=await client.Publish(seed,PkarrPacket.Create(seed,Math.Max(sequence+1,DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()*1000),next),deadline.Token);
            for(int attempt=0;attempt<4;attempt++){
                try{changed=(await client.Resolve(source,"faketcp",deadline.Token)).SequenceEqual(next.Endpoints);}catch(IOException){}
                if(changed)break;await Task.Delay(1000,deadline.Token);
            }
            Check(changed,"the same public discovery key returns the changed address after a new publication");
        }catch(Exception ex){error=ex.Message;throw;}
        finally{
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
            await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{status=first&&changed?"Pass":"Fail",checkedAt=DateTimeOffset.UtcNow,elapsedMs=watch.ElapsedMilliseconds,
                source,gateways=PkarrClient.DefaultGateways,firstAccepted=accepted,updateAccepted=updated,firstResolved=first,changedAddressResolved=changed,error,
                scope="Public HTTPS PKARR publication and signed address-change lookup only. Documentation addresses and ephemeral key; no installed profile, peer NAT traversal or streaming tested."},new JsonSerializerOptions{WriteIndented=true}));
        }
    }
}
