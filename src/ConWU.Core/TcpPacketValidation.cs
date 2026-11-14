using System.Buffers.Binary;

namespace StreamLink.Core;

// Offline/shared input contract after platform checksum normalization. It does
// not authenticate members; admission still requires the owned wire tuple.
internal static class TcpPacketValidation
{
    internal static bool Options(ReadOnlySpan<byte> options)
    {
        while(!options.IsEmpty){
            byte kind=options[0];if(kind==0)return true;
            if(kind==1){options=options[1..];continue;}
            if(options.Length<2)return false;
            int length=options[1];if(length<2||length>options.Length||kind==8&&length!=10)return false;
            options=options[length..];
        }
        return true;
    }
    static uint Sum(ReadOnlySpan<byte> value,uint sum=0)
    {
        while(value.Length>=2){sum+=BinaryPrimitives.ReadUInt16BigEndian(value);value=value[2..];}
        if(value.Length!=0)sum+=(uint)value[0]<<8;
        return sum;
    }
    static bool Correct(uint sum){while(sum>>16!=0)sum=(sum&65535)+(sum>>16);return sum==65535;}
    internal static bool Checksums(ReadOnlySpan<byte> packet)
    {
        if(!TcpCaptureOwner.Tuple(packet,out _,out _))return false;
        bool ipv6=packet[0]>>4==6;
        int ip=ipv6?40:(packet[0]&15)*4;
        int total=ipv6?40+BinaryPrimitives.ReadUInt16BigEndian(packet[4..]):BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        if(!ipv6&&!Correct(Sum(packet[..ip])))return false;
        uint sum=ipv6?Sum(packet.Slice(8,32)):Sum(packet.Slice(12,8));
        sum+=6u+(uint)(total-ip);
        return Correct(Sum(packet.Slice(ip,total-ip),sum));
    }
}
