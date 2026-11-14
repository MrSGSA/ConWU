using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    // This deliberately weak locator is an isolated feasibility probe, never
    // exposed by the product. A six-digit key derivation makes every reader a
    // publisher and collapses independent hosts into one public namespace.
    static async Task PkarrShortCodeFeasibility(string report)
    {
        static string Seed(string code)=>Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes("conwu-six-digit-feasibility-v1:"+code)));
        const string code="246810";
        string hostSeed=Seed(code),independentSeed=Seed(code),key=PkarrPacket.PublicKey(hostSeed);
        Check(PkarrPacket.PublicKey(independentSeed)==key,"independent hosts with the same six digits select the same PKARR locator");
        using var handler=new PkarrGateway();using var http=new HttpClient(handler);
        using var host=new PkarrClient(http,["https://fixture.invalid"]);
        using var other=new PkarrClient(http,["https://fixture.invalid"]);
        long sequence=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()*1000;
        var content=new PkarrAnnouncement(1,"faketcp",DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),["203.0.113.10:44680"]);
        await host.Publish(hostSeed,PkarrPacket.Create(hostSeed,sequence,content),default);
        Check((await host.Resolve("pkarr://"+key,"faketcp",default)).Single()==content.Endpoints[0],"six-digit-derived publication can be resolved through the real signed-packet client");
        var competing=content with{Endpoints=["203.0.113.99:44680"]};
        await other.Publish(independentSeed,PkarrPacket.Create(independentSeed,sequence+1000,competing),default);
        Check((await host.Resolve("pkarr://"+key,"faketcp",default)).Single()==competing.Endpoints[0],"someone knowing only the six digits can overwrite the locator with a valid newer signature");
        Check(handler.Publications==2,"the demonstration changes only an injected gateway, with no public publication or device configuration");
        var result=new{status="Completed",scope="Injected PKARR HTTP gateway and production signing/lookup; documentation addresses only",codeEntropyBits=Math.Log2(1_000_000),concurrentCodes=1000,approximateCollisionProbability=1-Math.Exp(-1000d*999/2_000_000),sameCodeSameLocator=true,readerCanDerivePublishingKey=true,overwriteReproduced=true,productionEnabled=false,conclusion="PKARR endpoints require a full public key. A global six-digit-only locator needs an additional index or a known discovery key; deriving the publishing key from six digits does not safely replace that index."};
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(report))!);
        await File.WriteAllTextAsync(report,JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));
        Console.WriteLine("PKARR six-digit feasibility probe completed; unsafe locator not enabled in product");
    }
}
