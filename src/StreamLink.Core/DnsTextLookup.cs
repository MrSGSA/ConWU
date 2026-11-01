using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace StreamLink.Core;

internal static class DnsTextLookup
{
    public static async Task<string[]> Query(string host,CancellationToken token)
    {
        var servers=NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.OperationalStatus==OperationalStatus.Up)
            .SelectMany(n=>n.GetIPProperties().DnsAddresses).Where(ip=>!ip.Equals(IPAddress.Any)&&!ip.Equals(IPAddress.IPv6Any)).Distinct().Take(2).ToArray();
        if(servers.Length==0)throw new IOException("未配置系统 DNS");
        ushort id=(ushort)RandomNumberGenerator.GetInt32(65536);
        var question=new List<byte>();
        foreach(var label in host.TrimEnd('.').Split('.')){question.Add((byte)label.Length);question.AddRange(Encoding.ASCII.GetBytes(label));}
        question.AddRange([0,0,16,0,1]);
        var request=new byte[12+question.Count];BinaryPrimitives.WriteUInt16BigEndian(request,id);request[2]=1;request[5]=1;question.CopyTo(request,12);
        foreach(var server in servers){
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(1800);
            try {
                using var socket=new Socket(server.AddressFamily,SocketType.Dgram,ProtocolType.Udp);
                await socket.ConnectAsync(new IPEndPoint(server,53),deadline.Token);
                await socket.SendAsync(request,SocketFlags.None,deadline.Token);
                var buffer=new byte[16384];int count=await socket.ReceiveAsync(buffer,SocketFlags.None,deadline.Token);
                if(count>=12 && (buffer[2]&2)!=0){
                    using var tcp=new TcpClient(server.AddressFamily);await tcp.ConnectAsync(server,53,deadline.Token);
                    var stream=tcp.GetStream();byte[] length=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(length,(ushort)request.Length);
                    await stream.WriteAsync(length,deadline.Token);await stream.WriteAsync(request,deadline.Token);
                    await stream.ReadExactlyAsync(length,deadline.Token);count=BinaryPrimitives.ReadUInt16BigEndian(length);
                    if(count>buffer.Length)throw new IOException("DNS 响应过大");await stream.ReadExactlyAsync(buffer.AsMemory(0,count),deadline.Token);
                }
                return Parse(buffer.AsSpan(0,count),id,question.ToArray());
            }catch(Exception ex)when(!token.IsCancellationRequested && ex is SocketException or IOException or OperationCanceledException){ }
        }
        token.ThrowIfCancellationRequested();throw new IOException("TXT 查询未完成");
    }
    internal static string[] Parse(ReadOnlySpan<byte> data,ushort id,ReadOnlySpan<byte> question)
    {
        if(data.Length<12+question.Length || BinaryPrimitives.ReadUInt16BigEndian(data)!=id || (data[2]&0xfa)!=0x80 || (data[3]&15)!=0 || BinaryPrimitives.ReadUInt16BigEndian(data[4..])!=1 || !data.Slice(12,question.Length).SequenceEqual(question))throw new IOException("DNS 响应无效");
        int count=BinaryPrimitives.ReadUInt16BigEndian(data[6..]);if(count>64)throw new IOException("DNS 记录过多");
        int at=12+question.Length;var values=new List<string>();
        for(int i=0;i<count;i++){
            SkipName(data,ref at);if(at+10>data.Length)throw new IOException("DNS 记录截断");
            int type=BinaryPrimitives.ReadUInt16BigEndian(data[at..]),cls=BinaryPrimitives.ReadUInt16BigEndian(data[(at+2)..]),len=BinaryPrimitives.ReadUInt16BigEndian(data[(at+8)..]);at+=10;
            if(at+len>data.Length)throw new IOException("DNS 内容截断");int end=at+len;
            if(type==16 && cls==1){var value=new StringBuilder();while(at<end){int size=data[at++];if(at+size>end)throw new IOException("TXT 内容截断");value.Append(Encoding.UTF8.GetString(data.Slice(at,size)));at+=size;}values.Add(value.ToString());}
            at=end;
        }
        if(values.Count==0)throw new IOException("未找到 TXT 入口");return values.ToArray();
    }
    static void SkipName(ReadOnlySpan<byte> data,ref int at)
    {
        int labels=0;while(at<data.Length && ++labels<=128){int size=data[at++];if(size==0)return;if((size&0xc0)==0xc0){if(at>=data.Length || (((size&63)<<8)|data[at++])>=data.Length)throw new IOException("DNS 指针无效");return;}if(size>63 || at+size>data.Length)throw new IOException("DNS 名称无效");at+=size;}throw new IOException("DNS 名称截断");
    }
}
