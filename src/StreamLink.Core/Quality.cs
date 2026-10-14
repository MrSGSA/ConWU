using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace StreamLink.Core;

public sealed record QualityResult(int RequestedMbps,int Seconds,int SentPackets,int ReceivedPackets,double ReceivedMbps,double LossPercent)
{
    public string Profile {get;init;}=QualityDiagnosticPolicy.Profile;
    public string EvidenceLayer {get;init;}="received inner UDP payload with one-second tail; not one-way deadline";
}
internal sealed record QualityMessage(string Op,ulong Id,int Mbps,int Seconds,int Count,string Mac,int Version=2,long NotAfter=0,string Initiator="",int InitiatorPort=0,string Responder="",string Error="");

public static class Quality
{
    public const int Port=47682;
    const int Size=1200,MaximumControl=1024;
    internal static string Mac(string key,QualityMessage m)=>Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(key),Encoding.UTF8.GetBytes("StreamLink/quality/manual-v2/"+JsonSerializer.Serialize(m with{Mac=""}))));
    static QualityMessage Sign(QualityMessage m,string key)=>m with{Mac=Mac(key,m)};
    internal static bool Valid(QualityMessage m,string key)
    {
        long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if(m.Version!=2||m.Op is not("start" or "cancel" or "done" or "denied")||m.Mbps is<1 or>60||m.Seconds is<1 or>20||m.Count is<0 or>200000||(m.Op is "start" or "cancel")&&m.Count!=0||
            m.NotAfter<now||m.NotAfter>now+60||m.InitiatorPort is<1 or>65535||!IPAddress.TryParse(m.Initiator,out _)||!IPAddress.TryParse(m.Responder,out _)||m.Mac?.Length!=64||m.Error is null||m.Error.Length>64)return false;
        try{return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(m.Mac),Convert.FromHexString(Mac(key,m)));}catch(FormatException){return false;}
    }
    public static Task Serve(string local,string peer,string key,CancellationToken token,QualityDiagnosticPolicy? policy=null)
        =>Serve(local,address=>address.Equals(IPAddress.Parse(peer))?key:null,token,policy);
    public static async Task Serve(string local,Func<IPAddress,string?> authorize,CancellationToken token,QualityDiagnosticPolicy? policy=null)
    {
        policy??=new(()=>false);
        using var socket=new UdpClient(new IPEndPoint(IPAddress.Parse(local),Port));
        var replies=new Dictionary<(IPAddress Address,ulong Id),QualityMessage>();
        Task? sending=null;CancellationTokenSource? sendingStop=null;QualityMessage? active=null;
        async Task Reply(QualityMessage message,string key,IPEndPoint remote){byte[] body=JsonSerializer.SerializeToUtf8Bytes(Sign(message,key));if(policy.ControlReplyAllowed(body.Length+28))await socket.SendAsync(body,remote,token);}
        async Task Send(QualityMessage request,string key,IPEndPoint remote,PathDiagnosticPermit permit,CancellationToken stop)
        {
            using(permit)using(var window=permit.Open(Guid.NewGuid(),Math.Min(100,(int)Math.Ceiling(request.Mbps*1.28)+1),request.Seconds*1000)){
                byte[] packet=RandomNumberGenerator.GetBytes(Size);"SLQ2"u8.CopyTo(packet);BinaryPrimitives.WriteUInt64BigEndian(packet.AsSpan(4),request.Id);
                var clock=Stopwatch.StartNew();int sent=0;
                try{
                    while(clock.Elapsed.TotalSeconds<request.Seconds&&window.Active&&policy.Allowed){
                        stop.ThrowIfCancellationRequested();
                        int target=(int)(clock.Elapsed.TotalSeconds*request.Mbps*1e6/(Size*8));
                        // A one-millisecond delay can resume on a coarser
                        // Windows tick. Sixteen packets per wake caps the test
                        // near 10 Mbps instead of generating the requested load.
                        // Catch up within a finite batch; every packet still
                        // spends the existing shared window/byte/rate budget.
                        for(int n=0;n<128&&sent<target;n++){
                            if(!window.Admit(QualityDiagnosticPolicy.WireDebitPerPacket))break;
                            BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(12),sent);await socket.SendAsync(packet,remote,stop);sent++;
                        }
                        await Task.Delay(1,stop);
                    }
                }catch(OperationCanceledException)when(stop.IsCancellationRequested){}
                var done=Sign(request with{Op="done",Count=sent},key);
                lock(replies){if(replies.Count>=64)replies.Remove(replies.Keys.First());replies[(remote.Address,request.Id)]=done;}
                if(!token.IsCancellationRequested)await Reply(done,key,remote);
            }
        }
        try{
            while(!token.IsCancellationRequested){
                var data=await socket.ReceiveAsync(token);if(data.Buffer.Length>MaximumControl)continue;
                string? key=authorize(data.RemoteEndPoint.Address);if(key==null)continue;
                QualityMessage? request;try{request=JsonSerializer.Deserialize<QualityMessage>(data.Buffer);}catch(JsonException){continue;}
                if(request==null||!Valid(request,key)||request.Initiator!=data.RemoteEndPoint.Address.ToString()||request.InitiatorPort!=data.RemoteEndPoint.Port||request.Responder!=local)continue;
                if(request.Op=="cancel"){
                    if(active is {} current&&current.Id==request.Id&&current.Initiator==request.Initiator&&current.InitiatorPort==request.InitiatorPort)sendingStop?.Cancel();continue;
                }
                if(request.Op!="start")continue;
                QualityMessage? prior;lock(replies)replies.TryGetValue((data.RemoteEndPoint.Address,request.Id),out prior);
                if(prior!=null&&prior.Mbps==request.Mbps&&prior.Seconds==request.Seconds&&prior.InitiatorPort==request.InitiatorPort){await Reply(prior,key,data.RemoteEndPoint);continue;}
                if(sending is{IsCompleted:false}){if(active?.Id!=request.Id)await Reply(request with{Op="denied",Error="Busy"},key,data.RemoteEndPoint);continue;}
                if(sending!=null){try{await sending;}catch(Exception)when(!token.IsCancellationRequested){}sending=null;}
                if(!policy.Allowed){await Reply(request with{Op="denied",Error="RemotePermissionRequired"},key,data.RemoteEndPoint);continue;}
                var permit=policy.Begin(Guid.NewGuid());
                if(permit==null){await Reply(request with{Op="denied",Error="DeviceBudgetOrCooldown"},key,data.RemoteEndPoint);continue;}
                sendingStop?.Dispose();sendingStop=CancellationTokenSource.CreateLinkedTokenSource(token);active=request;
                sending=Send(request,key,data.RemoteEndPoint,permit,sendingStop.Token);
            }
        }finally{
            sendingStop?.Cancel();if(sending!=null){try{await sending.WaitAsync(TimeSpan.FromSeconds(2));}catch(OperationCanceledException){} }
            sendingStop?.Dispose();
        }
    }

    public static async Task<QualityResult> Measure(string peer,string key,int mbps,CancellationToken token,int seconds=20,string? local=null,QualityDiagnosticPolicy? policy=null)
    {
        if(mbps is<1 or>60||seconds is<1 or>20)throw new ArgumentException("测速限于1–60 Mbps、1–20秒");
        policy??=new(()=>true);
        using var permit=policy.Begin(Guid.NewGuid())??throw new IOException("全机诊断额度占用或90秒冷却尚未结束");
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromSeconds(seconds+15));token=timeout.Token;
        using var socket=new UdpClient(new IPEndPoint(local==null?IPAddress.Any:IPAddress.Parse(local),0));socket.Client.ReceiveBufferSize=4*1024*1024;socket.Connect(IPAddress.Parse(peer),Port);
        var endpoint=(IPEndPoint)socket.Client.LocalEndPoint!;
        ulong id=BinaryPrimitives.ReadUInt64BigEndian(RandomNumberGenerator.GetBytes(8));
        var request=Sign(new("start",id,mbps,seconds,0,"",2,DateTimeOffset.UtcNow.AddSeconds(seconds+15).ToUnixTimeSeconds(),endpoint.Address.ToString(),endpoint.Port,peer),key);
        using var retries=CancellationTokenSource.CreateLinkedTokenSource(token);
        var repeat=Task.Run(async()=>{byte[] body=JsonSerializer.SerializeToUtf8Bytes(request);while(!retries.IsCancellationRequested){if(TraversalResources.Shared.TrySend(body.Length+28,maintenance:true))await socket.SendAsync(body,retries.Token);await Task.Delay(700,retries.Token);}},retries.Token);
        var seen=new HashSet<int>();QualityMessage? done=null;long doneAt=0;
        try{
            while(true){
                using var wait=CancellationTokenSource.CreateLinkedTokenSource(token);wait.CancelAfter(250);
                try{
                    var response=await socket.ReceiveAsync(wait.Token);var data=response.Buffer;
                    if(data.Length==Size&&data.AsSpan(0,4).SequenceEqual("SLQ2"u8)&&BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(4))==id){
                        int sequence=BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(12));if(sequence>=0&&sequence<200000)seen.Add(sequence);
                    }else if(data.Length<=MaximumControl){
                        try{var reply=JsonSerializer.Deserialize<QualityMessage>(data);if(reply?.Id==id&&reply.Mbps==mbps&&reply.Seconds==seconds&&reply.Initiator==request.Initiator&&reply.InitiatorPort==request.InitiatorPort&&reply.Responder==peer&&Valid(reply,key)){
                            if(reply.Op=="denied")throw new IOException("对端测速不可用："+reply.Error);
                            if(reply.Op=="done"){done=reply;if(doneAt==0)doneAt=Stopwatch.GetTimestamp();}
                        }}catch(JsonException){}
                    }
                }catch(OperationCanceledException)when(!token.IsCancellationRequested){}
                if(doneAt!=0&&Stopwatch.GetElapsedTime(doneAt).TotalSeconds>=1)break;
            }
        }finally{
            retries.Cancel();try{await repeat;}catch(OperationCanceledException){}
            if(done==null){
                using var cancel=new CancellationTokenSource(500);byte[] stop=JsonSerializer.SerializeToUtf8Bytes(Sign(request with{Op="cancel"},key));
                try{for(int n=0;n<3;n++){if(TraversalResources.Shared.TrySend(stop.Length+28,maintenance:true))await socket.SendAsync(stop,cancel.Token);await Task.Delay(25,cancel.Token);}}catch(Exception ex)when(ex is OperationCanceledException or SocketException){}
            }
        }
        if(done==null||done.Count<=0||seen.Count>done.Count)throw new IOException("测速未取得有效发送报告");
        return new(mbps,seconds,done.Count,seen.Count,seen.Count*Size*8d/seconds/1e6,100d*(done.Count-seen.Count)/done.Count);
    }
}
