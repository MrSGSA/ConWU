using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace StreamLink.Core;

public sealed record QualityResult(int RequestedMbps, int Seconds, int SentPackets, int ReceivedPackets, double ReceivedMbps, double LossPercent);
record QualityMessage(string Op, ulong Id, int Mbps, int Seconds, int Count, string Mac);

public static class Quality
{
    public const int Port = 47682;
    const int Size = 1200;
    static string Mac(string key, ulong id, int mbps, int seconds) => Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(key), Encoding.ASCII.GetBytes($"{id}:{mbps}:{seconds}")));
    static bool Valid(QualityMessage m, string key)
    {
        if (m.Mbps is < 1 or > 60 || m.Seconds is < 1 or > 20 || m.Mac?.Length != 64) return false;
        try { return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(m.Mac), Convert.FromHexString(Mac(key, m.Id, m.Mbps, m.Seconds))); } catch(FormatException) { return false; }
    }
    public static Task Serve(string local, string peer, string key, CancellationToken token)
        => Serve(local, address => address.Equals(IPAddress.Parse(peer)) ? key : null, token);
    public static async Task Serve(string local, Func<IPAddress, string?> authorize, CancellationToken token)
    {
        using var socket = new UdpClient(new IPEndPoint(IPAddress.Parse(local), Port));
        var replies = new Dictionary<(IPAddress Address, ulong Id), QualityMessage>();
        Task? sending = null;
        async Task Send(QualityMessage request, IPEndPoint remote)
        {
            byte[] packet = RandomNumberGenerator.GetBytes(Size); "SLQ1"u8.CopyTo(packet);
            BinaryPrimitives.WriteUInt64BigEndian(packet.AsSpan(4), request.Id);
            var clock = Stopwatch.StartNew(); int sent = 0;
            while(clock.Elapsed.TotalSeconds < request.Seconds && !token.IsCancellationRequested)
            {
                int target = (int)(clock.Elapsed.TotalSeconds * request.Mbps * 1e6 / (Size * 8));
                for(int n=0;n<128 && sent<target;n++)
                {
                    BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(12), sent);
                    await socket.SendAsync(packet, remote, token); sent++;
                }
                await Task.Delay(1, token);
            }
            var done = request with { Op = "done", Count = sent };
            lock(replies) { if(replies.Count >= 64) replies.Remove(replies.Keys.First()); replies[(remote.Address, request.Id)] = done; }
            await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(done), remote, token);
        }
        try
        {
            while(!token.IsCancellationRequested)
            {
                var data = await socket.ReceiveAsync(token);
                if(data.Buffer.Length > 512) continue;
                string? key = authorize(data.RemoteEndPoint.Address); if (key == null) continue;
                QualityMessage? request;
                try { request = JsonSerializer.Deserialize<QualityMessage>(data.Buffer); } catch(JsonException) { continue; }
                if(request == null || !Valid(request,key)) continue;
                QualityMessage? prior; lock(replies) replies.TryGetValue((data.RemoteEndPoint.Address, request.Id),out prior);
                if(prior != null) { await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(prior),data.RemoteEndPoint,token); continue; }
                if(request.Op == "start" && (sending == null || sending.IsCompleted)) sending = Send(request,data.RemoteEndPoint);
            }
        }
        finally { if(sending != null) { try { await sending; } catch(OperationCanceledException) { } } }
    }

    public static async Task<QualityResult> Measure(string peer, string key, int mbps, CancellationToken token, int seconds = 20, string? local = null)
    {
        if(mbps is < 1 or > 60 || seconds is < 1 or > 20) throw new ArgumentException("测速限于 1–60 Mbps、1–20 秒");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromSeconds(seconds + 15)); token = timeout.Token;
        using var socket = new UdpClient(new IPEndPoint(local == null ? IPAddress.Any : IPAddress.Parse(local), 0));
        socket.Client.ReceiveBufferSize = 4 * 1024 * 1024;
        socket.Connect(IPAddress.Parse(peer),Port);
        ulong id = BinaryPrimitives.ReadUInt64BigEndian(RandomNumberGenerator.GetBytes(8));
        var request = new QualityMessage("start",id,mbps,seconds,0,Mac(key,id,mbps,seconds));
        using var retries = CancellationTokenSource.CreateLinkedTokenSource(token);
        var repeat = Task.Run(async () => { while(!retries.IsCancellationRequested) { await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(request), retries.Token); await Task.Delay(700,retries.Token); } },retries.Token);
        var seen = new HashSet<int>(); QualityMessage? done = null; long doneAt = 0;
        try
        {
            while(true)
            {
                using var wait = CancellationTokenSource.CreateLinkedTokenSource(token); wait.CancelAfter(250);
                try
                {
                    var response = await socket.ReceiveAsync(wait.Token); var data = response.Buffer;
                    if(data.Length == Size && data.AsSpan(0,4).SequenceEqual("SLQ1"u8) && BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(4)) == id)
                    {
                        int sequence=BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(12));
                        if(sequence >= 0 && sequence < 200000) seen.Add(sequence);
                    }
                    else if(data.Length < 512)
                    {
                        try { var reply=JsonSerializer.Deserialize<QualityMessage>(data); if(reply?.Id==id && reply.Op=="done" && Valid(reply,key)) { done=reply; if(doneAt==0) doneAt=Stopwatch.GetTimestamp(); } } catch(JsonException) { }
                    }
                }
                catch(OperationCanceledException) when(!token.IsCancellationRequested) { }
                if(doneAt!=0 && Stopwatch.GetElapsedTime(doneAt).TotalSeconds >= 1) break;
            }
        }
        finally { retries.Cancel(); try { await repeat; } catch(OperationCanceledException) { } }
        if(done == null || done.Count <= 0 || seen.Count > done.Count) throw new IOException("测速未取得有效发送报告");
        return new(mbps,seconds,done.Count,seen.Count,seen.Count * Size * 8d / seconds / 1e6,100d * (done.Count - seen.Count) / done.Count);
    }
}
