using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace StreamLink.Core;

// A mailbox derived from the complete invitation lets a still-unpaired guest
// return its candidate. Invitation holders can write it: it is NOT a member
// identity or an authorization proof. SAS confirmation and host approval remain
// mandatory, and only a few small SYN probes may result from this hint.
public static class CompactPunchDiscovery
{
    const string Marker="conwu-mimic-first-contact-v1";
    public static string Seed(CompactDirectCode code)
    {
        if(code.Mode!="mimic"||!code.PunchDiscovery)throw new ArgumentException("此直连码未启用首次双向发现");
        return Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(Marker+"/"+CompactDirectCode.Issue(code.Endpoint,code.Mode,code.RoomCode,true))));
    }
    public static async Task Publish(PkarrClient client,CompactDirectCode code,IPEndPoint candidate,CancellationToken token)
    {
        if(!PortControlRoute.GlobalV4(candidate.Address)||candidate.Port==0)throw new IOException("从机尚无可公告的真实公网候选");
        var now=DateTimeOffset.UtcNow;string seed=Seed(code);
        var record=new PkarrAnnouncement(1,"mimic",now.AddSeconds(90).ToUnixTimeSeconds(),[candidate.ToString()]){State=Marker};
        byte[] packet=PkarrPacket.Create(seed,now.ToUnixTimeMilliseconds()*1000,record);
        await client.Publish(seed,packet,token);
    }
    public static async Task Listen(PkarrClient client,CompactDirectCode code,long expires,Action<IPEndPoint> punch,Action<string> log,CancellationToken token)
    {
        string source=PkarrPacket.Source(Seed(code));var candidates=new HashSet<string>();long lastLog=0;
        while(DateTimeOffset.UtcNow.ToUnixTimeSeconds()<expires){
            token.ThrowIfCancellationRequested();
            try{
                var record=await client.ResolveRecord(source,"mimic",token);
                if(record.Announcement.State!=Marker||record.Announcement.Endpoints.Length!=1||record.Announcement.Expires>DateTimeOffset.UtcNow.AddSeconds(100).ToUnixTimeSeconds())throw new IOException("首次探测公告不匹配");
                var text=record.Announcement.Endpoints[0];
                if(!IPEndPoint.TryParse(text,out var peer)||!PortControlRoute.GlobalV4(peer.Address)||peer.Port==0)throw new IOException("首次探测公告不是公网候选");
                if(candidates.Contains(text)||candidates.Count<8){candidates.Add(text);punch(peer);}
            }catch(Exception ex)when(!token.IsCancellationRequested&&ex is IOException or HttpRequestException or FormatException or OperationCanceledException){
                if(Environment.TickCount64-lastLog>30000){lastLog=Environment.TickCount64;log("首次双向发现仍在等待有效从机候选；现有配对会话保留");}
            }
            await Task.Delay(4000,token);
        }
    }
}
