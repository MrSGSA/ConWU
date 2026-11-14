using System.Buffers.Binary;
using System.Net;
using ConWU.Mobile;
using StreamLink.Core;

static class VpnTranslationTests
{
    static uint Address(string value)=>BinaryPrimitives.ReadUInt32BigEndian(IPAddress.Parse(value).GetAddressBytes());
    static ushort Read(ReadOnlySpan<byte> value,int offset)=>BinaryPrimitives.ReadUInt16BigEndian(value[offset..]);
    static void Write(Span<byte> value,int offset,int number)=>BinaryPrimitives.WriteUInt16BigEndian(value[offset..],(ushort)number);
    static ushort Checksum(ReadOnlySpan<byte> value){uint sum=0;for(int i=0;i<value.Length;i+=2)sum+=(uint)(value[i]<<8)+(i+1<value.Length?value[i+1]:0u);while(sum>>16!=0)sum=(sum&65535)+(sum>>16);return (ushort)~sum;}
    static byte[] Pseudo(byte[] packet){var bytes=new byte[12+packet.Length-20];packet.AsSpan(12,8).CopyTo(bytes);bytes[9]=packet[9];Write(bytes,10,packet.Length-20);packet.AsSpan(20).CopyTo(bytes.AsSpan(12));return bytes;}
    static bool ValidPayload(byte[] packet)=>packet[9]==1?Checksum(packet.AsSpan(20))==0:Checksum(Pseudo(packet))==0;
    static void Header(byte[] packet){Write(packet,2,packet.Length);Write(packet,10,0);Write(packet,10,Checksum(packet.AsSpan(0,20)));}
    static byte[] Packet(string source,string target,byte protocol)
    {
        byte[] bytes=new byte[96];bytes[0]=0x45;bytes[8]=64;bytes[9]=protocol;IPAddress.Parse(source).GetAddressBytes().CopyTo(bytes,12);IPAddress.Parse(target).GetAddressBytes().CopyTo(bytes,16);
        Random.Shared.NextBytes(bytes.AsSpan(20));
        if(protocol==1){bytes[20]=8;bytes[21]=0;Write(bytes,22,0);Write(bytes,22,Checksum(bytes.AsSpan(20)));}
        else{int offset=protocol==6?36:26;if(protocol==6)bytes[32]=0x50;else Write(bytes,24,bytes.Length-20);Write(bytes,offset,0);ushort check=Checksum(Pseudo(bytes));Write(bytes,offset,check==0?65535:check);}
        Header(bytes);return bytes;
    }
    public static async Task Run(Action<bool,string> check,IReadOnlyList<MobileNetwork> networks)
    {
        var first=networks[0];var second=networks[1];string system=first.Mesh.LocalIp,local=second.Mesh.LocalIp,remote=second.HostIp;
        foreach(byte protocol in new byte[]{1,6,17}){
            var outgoing=Packet(system,remote,protocol);MobileIpv4Translation.Rewrite(outgoing,12,Address(local));
            check(MeshPackets.Valid(outgoing)&&ValidPayload(outgoing)&&outgoing.AsSpan(12,4).SequenceEqual(IPAddress.Parse(local).GetAddressBytes()),"shared VPN translates outbound protocol "+protocol+" with valid IP and transport checksums");
            var incoming=Packet(remote,local,protocol);MobileIpv4Translation.Rewrite(incoming,16,Address(system));
            check(MeshPackets.Valid(incoming)&&ValidPayload(incoming),"shared VPN restores the OS destination for protocol "+protocol);
        }
        var noChecksum=Packet(system,remote,17);Write(noChecksum,26,0);MobileIpv4Translation.Rewrite(noChecksum,12,Address(local));
        check(Read(noChecksum,26)==0&&MeshPackets.Valid(noChecksum),"IPv4 UDP without a checksum retains its explicit zero checksum");
        var full=Packet(system,remote,6);var fragment=new byte[full.Length-16];full.AsSpan(0,20).CopyTo(fragment);full.AsSpan(36).CopyTo(fragment.AsSpan(20));Write(fragment,6,2);Header(fragment);
        MobileIpv4Translation.Rewrite(fragment,12,Address(local));
        IPAddress.Parse(local).GetAddressBytes().CopyTo(full,12);fragment.AsSpan(20).CopyTo(full.AsSpan(36));Header(full);
        check(MeshPackets.Valid(fragment)&&ValidPayload(full),"fragmented TCP checksum is adjusted in the fragment that actually contains it");
        var original=Packet(local,remote,17);var error=new byte[56];error[0]=0x45;error[8]=64;error[9]=1;IPAddress.Parse(remote).GetAddressBytes().CopyTo(error,12);IPAddress.Parse(local).GetAddressBytes().CopyTo(error,16);error[20]=3;error[21]=3;original.AsSpan(0,28).CopyTo(error.AsSpan(28));Write(error,22,Checksum(error.AsSpan(20)));Header(error);
        MobileIpv4Translation.Rewrite(error,16,Address(system));
        IPAddress.Parse(system).GetAddressBytes().CopyTo(original,12);Write(original,26,0);ushort expected=Checksum(Pseudo(original));if(expected==0)expected=65535;
        check(MeshPackets.Valid(error)&&ValidPayload(error)&&Read(error,54)==expected&&Checksum(error.AsSpan(28,20))==0,"ICMP errors restore the quoted local address, quoted UDP checksum and outer ICMP checksum");
        var observations=new System.Collections.Concurrent.ConcurrentQueue<(string Network,bool Received,string Local)>();
        var adapter=new TestAdapter();await using var hub=new MobilePacketHub(adapter,networks,system,(id,packet,received)=>observations.Enqueue((id,received,new IPAddress(packet.Span.Slice(received?16:12,4)).ToString())));var port=hub.Adapter(second.Id);
        adapter.Outgoing.Add(Packet(system,remote,17));byte[] buffer=new byte[MeshLink.Mtu];using var stop=new CancellationTokenSource(3000);int count=await Task.Run(()=>port.Read(buffer,stop.Token));
        check(MeshPackets.Valid(buffer.AsSpan(0,count))&&ValidPayload(buffer.AsSpan(0,count).ToArray())&&new IPAddress(buffer.AsSpan(12,4)).ToString()==local,"the second network receives the correct authenticated local IP from Android's common source");
        check(port.Write(Packet(remote,local,6))&&adapter.Received.TryPeek(out var restored)&&new IPAddress(restored.AsSpan(16,4)).ToString()==system&&ValidPayload(restored),"the second host's reply returns to the original OS socket with a valid checksum");
        check(observations.Count==2&&observations.All(o=>o.Network==second.Id&&o.Local==system)&&observations.Any(o=>o.Received)&&observations.Any(o=>!o.Received),"UU flow observers receive the exact network and OS-side socket addresses in both directions");
        int observed=observations.Count;check(!port.Write(Packet("203.0.113.9",local,17))&&observations.Count==observed,"unapproved packets cannot create successful VPN traffic observations");
    }
}
