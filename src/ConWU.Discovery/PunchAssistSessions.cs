using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.Discovery;

// Ephemeral hints only: no membership, arbitrary forwarding or persistent
// candidate database. HTTP source binding prevents third-party IP targets.
public sealed class PunchAssistSessions(TimeProvider? time=null)
{
    sealed class Participant(string token,IPAddress source,string commitment="",string requestId="")
    {public string Token=token,Commitment=commitment,RequestId=requestId,Endpoint="";public IPAddress Source=source;public bool Ready;}
    sealed class Room(string code,PunchAssistCreate input,Participant owner,long now,DateTimeOffset expires)
    {public string Code=code;public PunchAssistCreate Input=input;public Participant Owner=owner;public Participant? Guest;public long Created=now,Start;public DateTimeOffset Expires=expires;public Guid Round;}
    readonly object gate=new();
    readonly Dictionary<string,Room> rooms=[];
    readonly TimeProvider clock=time??TimeProvider.System;
    long totalScheduled;
    static string Token()=>Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    void Prune(){foreach(var key in rooms.Where(p=>clock.GetElapsedTime(p.Value.Created).TotalSeconds>=PunchAssistProtocol.InvitationSeconds).Select(p=>p.Key).ToArray())rooms.Remove(key);}
    static bool Same(string a,string b)=>PunchAssistProtocol.Secret(a)&&PunchAssistProtocol.Secret(b)&&CryptographicOperations.FixedTimeEquals(Convert.FromHexString(a),Convert.FromHexString(b));
    PunchAssistState State(Room room,Participant participant)
    {
        int delay=room.Round==Guid.Empty?0:PunchAssistProtocol.StartDelayMs-(int)clock.GetElapsedTime(room.Start).TotalMilliseconds;
        return new(room.Code,participant.Token,room.Expires.ToUnixTimeSeconds(),room.Input.HostRoom,room.Input.Commitment,room.Owner.Endpoint,room.Guest?.Endpoint??"",room.Round,Math.Max(-30000,delay),room.Input.Mode);
    }
    public PunchAssistState Create(PunchAssistCreate input,IPAddress source)
    {
        if(input==null||!TransportModes.TcpAssistance(input.Mode)||!PunchAssistProtocol.Code(input.HostRoom)||!PairKeyExchange.ValidCommitment(input.Commitment)||!PunchAssistProtocol.MatchesSource(input.Endpoint,source))throw new FormatException("辅助候选与实际来源或协议不符");
        lock(gate){Prune();if(rooms.Count>=PunchAssistProtocol.MaximumSessions)throw new IOException("打洞辅助会话容量已满");
            string code;do{code=RandomNumberGenerator.GetInt32(1_000_000).ToString("D6");}while(rooms.ContainsKey(code));
            var owner=new Participant(Token(),source){Endpoint=input.Endpoint,Ready=input.Ready};
            var room=new Room(code,input,owner,clock.GetTimestamp(),clock.GetUtcNow().AddSeconds(PunchAssistProtocol.InvitationSeconds));rooms.Add(code,room);return State(room,owner);
        }
    }
    public PunchAssistState Join(PunchAssistJoin input,IPAddress source)
    {
        if(input==null||!PunchAssistProtocol.Code(input.Code)||!Guid.TryParseExact(input.RequestId,"N",out _)||!PairKeyExchange.ValidCommitment(input.Commitment))throw new FormatException();
        lock(gate){Prune();if(!rooms.TryGetValue(input.Code,out var room))throw new KeyNotFoundException();
            if(input.Mode!=room.Input.Mode)throw new IOException("辅助会话的传输协议不同");
            if(room.Guest==null)room.Guest=new(Token(),source,input.Commitment,input.RequestId);
            else if(!room.Guest.Source.Equals(source)||room.Guest.Commitment!=input.Commitment||room.Guest.RequestId!=input.RequestId)throw new IOException("会话已有其他申请");
            return State(room,room.Guest);
        }
    }
    public PunchAssistState Update(string code,PunchAssistUpdate input,IPAddress source)
    {
        if(!PunchAssistProtocol.Code(code)||input==null||!PunchAssistProtocol.Secret(input.Token)||input.Endpoint is not {Length:<=64})throw new FormatException();
        lock(gate){Prune();if(!rooms.TryGetValue(code,out var room))throw new KeyNotFoundException();
            var participant=Same(input.Token,room.Owner.Token)?room.Owner:room.Guest!=null&&Same(input.Token,room.Guest.Token)?room.Guest:throw new UnauthorizedAccessException();
            if(!participant.Source.Equals(source))throw new UnauthorizedAccessException();
            if(input.Close){if(participant!=room.Owner)throw new UnauthorizedAccessException();var result=State(room,participant);rooms.Remove(code);return result;}
            if(input.Endpoint.Length>0){
                if(!PunchAssistProtocol.MatchesSource(input.Endpoint,source)||participant.Endpoint.Length>0&&participant.Endpoint!=input.Endpoint)throw new IOException("候选已变化或与来源不符");
                participant.Endpoint=input.Endpoint;
            }
            participant.Ready=input.Ready;
            if(room.Round==Guid.Empty&&room.Owner.Ready&&room.Guest is {Ready:true,Endpoint.Length:>0}){room.Round=Guid.NewGuid();room.Start=clock.GetTimestamp();totalScheduled++;}
            return State(room,participant);
        }
    }
    public PunchAssistStatus Status{get{lock(gate){Prune();return new(rooms.Values.Count(r=>r.Round==Guid.Empty),rooms.Values.Count(r=>r.Round!=Guid.Empty),totalScheduled);}}}
}
