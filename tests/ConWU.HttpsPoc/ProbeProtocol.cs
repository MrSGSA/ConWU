using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using StreamLink.Core;

namespace ConWU.HttpsPoc;

static class ProbeProtocol
{
    public const string Subprotocol="conwu.https-poc.v1",Path="/conwu/stream";
    public const int MaximumMessage=MeshLink.Mtu+MeshLink.Overhead;
    public static string Token()=>Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    public static byte[] Key(string token)=>HKDF.DeriveKey(HashAlgorithmName.SHA256,Encoding.UTF8.GetBytes(token),32,info:"conwu-https-poc-mesh-v1"u8.ToArray());
    public static string Pin(X509Certificate certificate)=>Convert.ToHexString(SHA256.HashData(certificate.GetRawCertData()));
    public static string ValidatePin(string pin)
    {
        if(pin.Length!=64||!pin.All(char.IsAsciiHexDigit))throw new ArgumentException("Certificate pin must contain 64 hex characters");
        return pin.ToUpperInvariant();
    }
    public static RemoteCertificateValidationCallback Trust(string pin)
    {
        byte[] expected=Convert.FromHexString(ValidatePin(pin));
        return (_,certificate,_,_)=>{
            if(certificate==null)return false;
            using var parsed=new X509Certificate2(certificate);
            return DateTime.UtcNow>=parsed.NotBefore.ToUniversalTime()&&DateTime.UtcNow<=parsed.NotAfter.ToUniversalTime()&&
                CryptographicOperations.FixedTimeEquals(expected,SHA256.HashData(parsed.RawData));
        };
    }
    public static Uri Endpoint(string text)
    {
        if(!Uri.TryCreate(text,UriKind.Absolute,out var url)||url.Scheme is not ("https" or "wss")||url.UserInfo.Length>0||url.Query.Length>0||url.Fragment.Length>0)
            throw new ArgumentException("Use a direct https://host:port/conwu/stream endpoint without credentials or query parameters");
        return new UriBuilder(url){Scheme="wss",Path=url.AbsolutePath=="/"?Path:url.AbsolutePath}.Uri;
    }
    public static async Task<byte[]?> Read(WebSocket socket,CancellationToken token)
    {
        byte[] buffer=new byte[MaximumMessage];int used=0;
        while(true){
            var part=await socket.ReceiveAsync(buffer.AsMemory(used),token);
            if(part.MessageType==WebSocketMessageType.Close)return null;
            if(part.MessageType!=WebSocketMessageType.Binary)throw new ProbeProtocolException(WebSocketCloseStatus.InvalidMessageType,"Binary messages required");
            used+=part.Count;
            if(part.EndOfMessage){if(used<MeshLink.Overhead)throw new ProbeProtocolException(WebSocketCloseStatus.InvalidPayloadData,"Truncated encrypted datagram");return buffer[..used];}
            if(used==buffer.Length)throw new ProbeProtocolException(WebSocketCloseStatus.MessageTooBig,"Datagram exceeds the negotiated MTU");
        }
    }
    public static byte[] Payload(long sequence,int length)
    {
        if(length is <64 or >MeshLink.Mtu)throw new ArgumentOutOfRangeException(nameof(length));
        byte[] bytes=new byte[length];"CHP1"u8.CopyTo(bytes);BinaryPrimitives.WriteInt64BigEndian(bytes.AsSpan(4),sequence);
        BinaryPrimitives.WriteInt64BigEndian(bytes.AsSpan(12),Stopwatch.GetTimestamp());
        for(int i=20;i<length;i++)bytes[i]=(byte)(sequence+i*17);
        return bytes;
    }
    public static (long Sequence,long Timestamp) Inspect(byte[] bytes)
    {
        if(bytes.Length<64||!bytes.AsSpan(0,4).SequenceEqual("CHP1"u8))throw new IOException("Echo payload header is invalid");
        long sequence=BinaryPrimitives.ReadInt64BigEndian(bytes.AsSpan(4)),timestamp=BinaryPrimitives.ReadInt64BigEndian(bytes.AsSpan(12));
        for(int i=20;i<bytes.Length;i++)if(bytes[i]!=(byte)(sequence+i*17))throw new IOException("Echo payload differs from the sent datagram");
        return(sequence,timestamp);
    }
}
sealed class ProbeProtocolException(WebSocketCloseStatus status,string message):IOException(message)
{
    public WebSocketCloseStatus Status{get;}=status;
}
sealed class Latencies
{
    readonly long[] buckets=new long[100001];long count;double maximum;
    public void Add(double milliseconds){buckets[Math.Clamp((int)(milliseconds*10),0,buckets.Length-1)]++;count++;maximum=Math.Max(maximum,milliseconds);}
    double Percentile(double fraction){long target=(long)Math.Ceiling(count*fraction),sum=0;for(int i=0;i<buckets.Length;i++){sum+=buckets[i];if(sum>=target)return i/10d;}return 0;}
    public object Report()=>new{samples=count,p50Ms=Percentile(.5),p95Ms=Percentile(.95),p99Ms=Percentile(.99),maxMs=maximum,histogramResolutionMs=.1,histogramOverflowMs=10000};
}
