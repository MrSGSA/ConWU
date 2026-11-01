using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace StreamLink.Core;

public sealed record DirectPairRequest(string Id,string Method,string Room="",string Token="",string Code="",string Commitment="",string Name="",string PublicKey="",int Offset=0);
public sealed record DirectPairReply(string Id,string Error="",PairRoomTicket? Ticket=null,PairRoomState? State=null,string Part="",int Total=0);
public static class DirectPairWire
{
    // A protocol identifier, NOT a secret or a business authentication key.
    // This lets an un-enrolled device reach the bounded invitation service on
    // the same selected-protocol listener. MeshLink still authenticates every
    // business packet with independently derived per-member keys.
    public const string CarriageKey="streamlink-direct-rendezvous-v1";
    public const int MaximumDatagram=1200, MaximumCipher=44000, Chunk=800;
    public static bool IsFrame(ReadOnlySpan<byte> packet)=>packet.Length>=4&&packet[..4].SequenceEqual("SLP1"u8);
    public static byte[] Encode<T>(T value){var body=JsonSerializer.SerializeToUtf8Bytes(value,new JsonSerializerOptions{Encoder=System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping});if(body.Length>MaximumDatagram-4)throw new IOException("直连配对消息过大");return "SLP1"u8.ToArray().Concat(body).ToArray();}
    public static T Decode<T>(ReadOnlySpan<byte> packet)=>IsFrame(packet)&&packet.Length<=MaximumDatagram?JsonSerializer.Deserialize<T>(packet[4..],new JsonSerializerOptions{MaxDepth=8})??throw new FormatException("配对消息为空"):throw new FormatException("配对消息无效");
}

// One expiring room, one candidate, bounded replies. Local owner operations
// are never available over the network. Six digits locate the room; committed
// ECDH keys + human SAS confirmation authenticate the encrypted enrollment.
public sealed class DirectPairHost : IShortPairClient
{
    readonly object gate=new();
    readonly TimeProvider clock;
    PairRoomTicket? ticket,guest;
    PairRoomState? state;
    long window;int replies,badCodes;bool delivered;
    public DirectPairHost(TimeProvider? clock=null)=>this.clock=clock??TimeProvider.System;
    static string Token()=>Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    static bool Equal(string a,string b)=>a!=null&&b!=null&&a.Length==b.Length&&CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a),Encoding.UTF8.GetBytes(b));
    void Live(){if(ticket==null||ticket.Expires<=clock.GetUtcNow().ToUnixTimeSeconds())throw new IOException("配对码无效或已过期，请主机重新生成");}
    public void Clear(){lock(gate){ticket=guest=null;state=null;badCodes=0;delivered=false;}}
    public Task<PairRoomTicket> Create(PairKeyExchange key,string name,CancellationToken cancel){lock(gate){cancel.ThrowIfCancellationRequested();if(state?.Approved==true&&!delivered&&ticket!.Expires>clock.GetUtcNow().ToUnixTimeSeconds())throw new IOException("上一台设备正在接收授权，请稍后再生成配对码");Clear();ticket=new(Guid.NewGuid().ToString("N"),RandomNumberGenerator.GetInt32(1_000_000).ToString("D6"),Token(),key.Commitment,name,clock.GetUtcNow().AddMinutes(5).ToUnixTimeSeconds());state=new("","","","","","",false,ticket.Expires){Addressing=1};return Task.FromResult(ticket);}}
    public Task<PairRoomTicket> Join(string code,PairKeyExchange key,string name,CancellationToken cancel,string requestedIp="")=>throw new NotSupportedException();
    void Owner(PairRoomTicket value){Live();if(value.Room!=ticket!.Room||!Equal(value.Token,ticket.Token))throw new IOException("配对会话已改变");}
    public Task<PairRoomState> Poll(PairRoomTicket value,bool owner,CancellationToken cancel){lock(gate){cancel.ThrowIfCancellationRequested();if(!owner)throw new InvalidOperationException();Owner(value);return Task.FromResult(state!);}}
    public Task<PairRoomState> Reveal(PairRoomTicket value,bool owner,PairKeyExchange key,CancellationToken cancel){lock(gate){Owner(value);if(!owner||guest==null||state!.Outcome.Length>0||state.Approved)throw new IOException("配对状态已改变");PairKeyExchange.ValidatePublic(key.PublicKey,ticket!.HostCommitment);state=state with{HostPublic=key.PublicKey};return Task.FromResult(state);}}
    public Task<PairRoomState> Approve(PairRoomTicket value,string candidate,string cipher,CancellationToken cancel){lock(gate){Owner(value);if(state!.Candidate!=candidate||state.GuestPublic.Length==0||state.HostPublic.Length==0||state.Outcome.Length>0||cipher.Length is <40 or >DirectPairWire.MaximumCipher)throw new IOException("配对申请已改变");if(state.Approved&&!Equal(state.Ciphertext,cipher))throw new IOException("不能替换已签发的授权");state=state with{Approved=true,Ciphertext=cipher};return Task.FromResult(state);}}
    public Task Close(PairRoomTicket value,CancellationToken cancel){lock(gate){if(ticket?.Room==value.Room&&Equal(ticket.Token,value.Token))Clear();return Task.CompletedTask;}}
    public Task<PairRoomState> Finish(PairRoomTicket value,bool owner,CancellationToken cancel){lock(gate){Owner(value);if(!owner||state!.Approved)throw new IOException("已签发授权，请从设备列表移除");state=state with{Outcome="Rejected"};return Task.FromResult(state);}}
    public byte[]? Handle(ReadOnlyMemory<byte> packet)
    {
        lock(gate){
            if(ticket==null||ticket.Expires<=clock.GetUtcNow().ToUnixTimeSeconds()||packet.Length>DirectPairWire.MaximumDatagram)return null;
            long now=clock.GetTimestamp();if(clock.GetElapsedTime(window,now).TotalSeconds>=1){window=now;replies=0;}if(++replies>5)return null;
            DirectPairRequest request;
            try{request=DirectPairWire.Decode<DirectPairRequest>(packet.Span);if(!Guid.TryParseExact(request.Id,"N",out _))return null;}catch{return null;}
            try{return DirectPairWire.Encode(HandleRequest(request));}
            catch(Exception ex)when(ex is IOException or FormatException or CryptographicException or ArgumentException){return DirectPairWire.Encode(new DirectPairReply(request.Id,"配对请求无效、已过期或状态已改变，请核对入口和配对码"));}
        }
    }
    DirectPairReply HandleRequest(DirectPairRequest r)
    {
        Live();
        if(r.Method=="join"){
            if(r.Code is not {Length:6}||!Equal(r.Code,ticket!.Code)){if(++badCodes>=20)Clear();throw new IOException();}
            if(!PairKeyExchange.ValidCommitment(r.Commitment)||r.Name is not {Length:>0 and <=64}||r.Name.Any(char.IsControl)||state!.Approved||state.Outcome.Length>0)throw new IOException();
            if(guest!=null){if(state.GuestCommitment!=r.Commitment||state.GuestName!=r.Name)throw new IOException();return new(r.Id,Ticket:guest);}
            guest=new(ticket.Room,"",Token(),ticket.HostCommitment,ticket.HostName,ticket.Expires,Guid.NewGuid().ToString("N"));
            state=state with{Candidate=guest.Candidate,GuestCommitment=r.Commitment,GuestName=r.Name};return new(r.Id,Ticket:guest);
        }
        if(guest==null||r.Room!=guest.Room||!Equal(r.Token,guest.Token))throw new IOException();
        switch(r.Method){
            case "poll":break;
            case "reveal":
                if(state!.HostPublic.Length==0||state.Outcome.Length>0||state.Approved)throw new IOException();
                PairKeyExchange.ValidatePublic(r.PublicKey,state.GuestCommitment);state=state with{GuestPublic=r.PublicKey};break;
            case "cancel":if(state!.Approved)throw new IOException();state=state with{Outcome="Cancelled"};break;
            case "received":if(!state!.Approved)throw new IOException();delivered=true;break;
            case "chunk":
                if(!state!.Approved||r.Offset<0||r.Offset>=state.Ciphertext.Length||r.Offset%DirectPairWire.Chunk!=0)throw new IOException();
                return new(r.Id,Part:state.Ciphertext.Substring(r.Offset,Math.Min(DirectPairWire.Chunk,state.Ciphertext.Length-r.Offset)),Total:state.Ciphertext.Length);
            default:throw new IOException();
        }
        return new(r.Id,State:state! with{Ciphertext=""},Total:state!.Approved?state.Ciphertext.Length:0);
    }
    // UI releases its local handle after approving; the encrypted reply remains
    // available until expiry or a new explicit invitation. Worker owns Clear.
    public void Dispose(){}
}

public sealed class DirectPairClient : IShortPairClient
{
    readonly UdpClient socket=new(new IPEndPoint(IPAddress.Loopback,0));
    readonly IMeshTransport transport;
    readonly IPEndPoint target;
    readonly SemaphoreSlim gate=new(1,1);
    readonly CancellationTokenSource lifetime=new();
    readonly Timer expiry;
    Exception? disposalError;
    int disposed;
    public DirectPairClient(Func<IPEndPoint,IMeshTransport> factory){try{transport=factory((IPEndPoint)socket.Client.LocalEndPoint!);target=transport.ClientEndpoint??throw new IOException("配对传输未提供本地端口");expiry=new(_=>{try{Dispose();}catch(Exception ex){Volatile.Write(ref disposalError,ex);}},null,TimeSpan.FromMinutes(6),Timeout.InfiniteTimeSpan);}catch{try{transport?.Dispose();}finally{socket.Dispose();lifetime.Dispose();}throw;}}
    async Task<DirectPairReply> Send(DirectPairRequest request,CancellationToken cancel)
    {
        if(Volatile.Read(ref disposed)!=0)throw new IOException("直连配对已结束或超时，请重新申请");
        await gate.WaitAsync(cancel);
        try{
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancel,lifetime.Token);deadline.CancelAfter(10000);
            var packet=DirectPairWire.Encode(request);Task<UdpReceiveResult>? pending=null;
            try{while(true){
                deadline.Token.ThrowIfCancellationRequested();if(transport.Exited)throw new IOException("主机入口的配对传输已退出，请检查协议和端口");
                await socket.SendAsync(packet,target,deadline.Token);
                long until=Environment.TickCount64+500;
                while(Environment.TickCount64<until){
                    pending??=socket.ReceiveAsync(deadline.Token).AsTask();
                    if(await Task.WhenAny(pending,Task.Delay((int)Math.Max(1,until-Environment.TickCount64),deadline.Token))!=pending)break;
                    UdpReceiveResult received;
                    try{received=await pending;}catch(SocketException ex)when(ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize){pending=null;continue;}
                    pending=null;if(!received.RemoteEndPoint.Equals(target))continue;
                    DirectPairReply reply;try{reply=DirectPairWire.Decode<DirectPairReply>(received.Buffer);}catch{continue;}
                    if(reply.Id!=request.Id)continue;if(reply.Error.Length>0)throw new IOException(reply.Error);return reply;
                }
            }}catch(OperationCanceledException)when(!cancel.IsCancellationRequested){throw new IOException("主机入口未回应配对。请确认主机已生成短码、入口指向 StreamLink，且双方协议相同");}
            finally{deadline.Cancel();if(pending!=null)try{await pending;}catch(OperationCanceledException){}catch(SocketException){}}
        }finally{gate.Release();}
    }
    static DirectPairRequest Request(string method,PairRoomTicket? ticket=null)=>new(Guid.NewGuid().ToString("N"),method,ticket?.Room??"",ticket?.Token??"");
    public Task<PairRoomTicket> Create(PairKeyExchange key,string name,CancellationToken cancel)=>throw new NotSupportedException();
    public async Task<PairRoomTicket> Join(string code,PairKeyExchange key,string name,CancellationToken cancel,string requestedIp="")
    {
        if(code.Length!=6||code.Any(c=>c<'0'||c>'9'))throw new FormatException("请输入六位配对码");
        var ticket=(await Send(Request("join") with{Code=code,Commitment=key.Commitment,Name=name},cancel)).Ticket??throw new IOException("主机没有返回配对申请");
        if(!Guid.TryParseExact(ticket.Room,"N",out _)||!Guid.TryParseExact(ticket.Candidate,"N",out _)||ticket.Token.Length!=64||!PairKeyExchange.ValidCommitment(ticket.HostCommitment)||ticket.Expires<=DateTimeOffset.UtcNow.ToUnixTimeSeconds()||ticket.Expires>DateTimeOffset.UtcNow.AddMinutes(6).ToUnixTimeSeconds()||ticket.HostName.Length>64)throw new IOException("主机配对响应无效");return ticket;
    }
    async Task<PairRoomState> State(DirectPairRequest request,CancellationToken cancel)
    {
        var reply=await Send(request,cancel);var state=reply.State??throw new IOException("配对状态为空");
        if(!state.Approved)return state;
        if(reply.Total is <40 or >DirectPairWire.MaximumCipher)throw new IOException("授权长度无效");
        var text=new StringBuilder(reply.Total);
        for(int offset=0;offset<reply.Total;offset+=DirectPairWire.Chunk){
            var chunk=await Send(request with{Id=Guid.NewGuid().ToString("N"),Method="chunk",Offset=offset},cancel);
            if(chunk.Total!=reply.Total||chunk.Part.Length!=Math.Min(DirectPairWire.Chunk,reply.Total-offset))throw new IOException("授权分片无效");text.Append(chunk.Part);
        }
        await Send(request with{Id=Guid.NewGuid().ToString("N"),Method="received"},cancel);
        return state with{Ciphertext=text.ToString()};
    }
    public Task<PairRoomState> Poll(PairRoomTicket ticket,bool owner,CancellationToken cancel)=>!owner?State(Request("poll",ticket),cancel):throw new InvalidOperationException();
    public Task<PairRoomState> Reveal(PairRoomTicket ticket,bool owner,PairKeyExchange key,CancellationToken cancel)=>!owner?State(Request("reveal",ticket) with{PublicKey=key.PublicKey},cancel):throw new InvalidOperationException();
    public Task<PairRoomState> Approve(PairRoomTicket ticket,string candidate,string cipher,CancellationToken cancel)=>throw new NotSupportedException();
    public Task Close(PairRoomTicket ticket,CancellationToken cancel)=>Task.CompletedTask;
    public Task<PairRoomState> Finish(PairRoomTicket ticket,bool owner,CancellationToken cancel)=>!owner?State(Request("cancel",ticket),cancel):throw new InvalidOperationException();
    public void Dispose(){if(Interlocked.Exchange(ref disposed,1)!=0){if(Volatile.Read(ref disposalError) is {} error)throw new IOException("配对传输退出未获证实",error);return;}expiry.Dispose();lifetime.Cancel();try{transport.Dispose();}catch(Exception ex){Volatile.Write(ref disposalError,ex);throw;}finally{socket.Dispose();}}
}
