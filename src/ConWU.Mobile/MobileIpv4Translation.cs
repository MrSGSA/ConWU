using System.Buffers.Binary;

namespace ConWU.Mobile;

// Android selects one VPN source address across all peer /32 routes. Translate
// only the local address at this boundary, before/after per-network AEAD. Peer
// addresses and transport ports are unchanged, so each OS socket keeps its flow.
internal static class MobileIpv4Translation
{
    static ushort Read(ReadOnlySpan<byte> bytes,int offset)=>BinaryPrimitives.ReadUInt16BigEndian(bytes[offset..]);
    static void Write(Span<byte> bytes,int offset,ushort value)=>BinaryPrimitives.WriteUInt16BigEndian(bytes[offset..],value);
    static ushort Fold(uint sum){while(sum>>16!=0)sum=(sum&65535)+(sum>>16);return (ushort)~sum;}
    static ushort Adjust(ushort checksum,uint before,uint after)
        =>Fold((uint)(~checksum&65535)+(~(before>>16)&65535)+(after>>16)+(~before&65535)+(after&65535));
    public static void Rewrite(Span<byte> packet,int addressOffset,uint replacement)=>Rewrite(packet,addressOffset,replacement,false);
    static void Rewrite(Span<byte> packet,int addressOffset,uint replacement,bool quoted)
    {
        if(packet.Length<20)return;
        int header=(packet[0]&15)*4;
        if(packet[0]>>4!=4||header<20||header>packet.Length)return;
        uint original=BinaryPrimitives.ReadUInt32BigEndian(packet[addressOffset..]);
        if(original==replacement)return;
        Write(packet,10,Adjust(Read(packet,10),original,replacement));
        BinaryPrimitives.WriteUInt32BigEndian(packet[addressOffset..],replacement);
        int fragmentOffset=(Read(packet,6)&8191)*8;
        int checksumOffset=packet[9] switch{6=>16,17 or 136=>6,_=>-1};
        int index=header+checksumOffset-fragmentOffset;
        if(checksumOffset>=0&&index>=header&&index+2<=packet.Length){
            ushort prior=Read(packet,index);
            if(packet[9]!=17||prior!=0){ushort value=Adjust(prior,original,replacement);Write(packet,index,value==0&&packet[9] is 17 or 136?(ushort)65535:value);}
        }
        // ICMP errors quote the packet that caused them. Restore that packet's
        // opposite local address as well, including its checksums when present.
        if(!quoted&&packet[9]==1&&fragmentOffset==0&&packet.Length>=header+28&&packet[header] is 3 or 11 or 12){
            var quote=packet[(header+8)..];int opposite=addressOffset==12?16:12;
            if(quote[0]>>4==4&&BinaryPrimitives.ReadUInt32BigEndian(quote[opposite..])==original){
                byte[] before=quote.ToArray();Rewrite(quote,opposite,replacement,true);
                uint sum=(uint)(~Read(packet,header+2)&65535);
                for(int i=0;i<quote.Length;i+=2){uint old=(uint)(before[i]<<8)+(i+1<before.Length?before[i+1]:0u),next=(uint)(quote[i]<<8)+(i+1<quote.Length?quote[i+1]:0u);sum+=(~old&65535)+next;}
                Write(packet,header+2,Fold(sum));
            }
        }
    }
}
