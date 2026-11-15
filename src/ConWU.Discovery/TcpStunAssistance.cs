using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using Microsoft.AspNetCore.Connections;

namespace StreamLink.Discovery;

// Multiplex standard TCP STUN before TLS, on the same owned listener. Only
// binding requests are answered to their existing TCP connection. There is no
// UDP socket, destination parameter or relay operation.
internal static class TcpStunAssistance
{
    public static async Task Handle(ConnectionContext connection,ConnectionDelegate next)
    {
        var reader=connection.Transport.Input;var writer=connection.Transport.Output;
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(connection.ConnectionClosed);
        try{
            stop.CancelAfter(10000);
            var first=await reader.ReadAsync(stop.Token);
            if(first.Buffer.IsEmpty){reader.AdvanceTo(first.Buffer.End);return;}
            bool stun=first.Buffer.FirstSpan[0]==0;
            reader.AdvanceTo(first.Buffer.Start,first.Buffer.Start);
            if(!stun){stop.CancelAfter(Timeout.Infinite);await next(connection);return;}
            var remote=connection.RemoteEndPoint as IPEndPoint;
            if(remote?.Address.IsIPv4MappedToIPv6==true)remote=new(remote.Address.MapToIPv4(),remote.Port);
            if(remote?.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork)return;
            long window=Environment.TickCount64;int requests=0;
            while(!stop.IsCancellationRequested){
                stop.CancelAfter(45000);
                var read=await reader.ReadAsync(stop.Token);var buffer=read.Buffer;
                if(buffer.Length<20){reader.AdvanceTo(buffer.Start,buffer.End);if(read.IsCompleted)return;continue;}
                byte[] request=buffer.Slice(0,20).ToArray();
                if(BinaryPrimitives.ReadUInt16BigEndian(request)!=1||BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(2))!=0||BinaryPrimitives.ReadUInt32BigEndian(request.AsSpan(4))!=0x2112a442)return;
                if(Environment.TickCount64-window>=60000){window=Environment.TickCount64;requests=0;}
                if(++requests>12)return;
                reader.AdvanceTo(buffer.GetPosition(20));
                byte[] response=new byte[32];request.CopyTo(response,0);BinaryPrimitives.WriteUInt16BigEndian(response,0x0101);BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2),12);
                BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(20),0x20);BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(22),8);response[25]=1;
                BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(26),(ushort)(remote.Port^0x2112));
                var address=remote.Address.GetAddressBytes();for(int i=0;i<4;i++)response[28+i]=(byte)(address[i]^request[4+i]);
                await writer.WriteAsync(response,stop.Token);
            }
        }catch(Exception ex)when(ex is IOException or OperationCanceledException or System.Net.Sockets.SocketException){}
    }
}
