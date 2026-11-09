using System.Net;
using System.Net.Sockets;
using System.Text;

namespace StreamLink.Core;

// Version/protocol (4), IPv4 (32), port (16), room locator (20), CRC-8 (8).
// The checksum detects transcription errors. Authentication still requires
// committed key exchange, comparison of the SAS, and explicit host approval.
public sealed record CompactDirectCode(string Endpoint,string Mode,string RoomCode)
{
    public const int Symbols=16,MaximumTextLength=64;
    const string Alphabet="0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    const int Version=1;
    static byte Checksum(ReadOnlySpan<byte> bytes)
    {
        byte crc=0;
        foreach(byte b in bytes){crc^=b;for(int bit=0;bit<8;bit++)crc=(byte)((crc&0x80)!=0?(crc<<1)^0x07:crc<<1);}
        return crc;
    }
    public static string Issue(string endpoint,string mode,string roomCode)
    {
        if(mode is not ("faketcp" or "udp")||roomCode is not {Length:6}||!roomCode.All(char.IsAsciiDigit))throw new FormatException("直连码的协议或配对会话无效");
        var parsed=ExistingEntryResolver.ParseEndpoint(endpoint);
        if(!IPAddress.TryParse(parsed.Host,out var address)||address.AddressFamily!=AddressFamily.InterNetwork)throw new FormatException("直连码需要已解析的 IPv4 入口");
        var ip=address.GetAddressBytes();uint number=((uint)ip[0]<<24)|((uint)ip[1]<<16)|((uint)ip[2]<<8)|ip[3];
        UInt128 body=((UInt128)((Version<<1)|(mode=="udp"?1:0))<<68)|((UInt128)number<<36)|((UInt128)(uint)parsed.Port<<20)|(uint)int.Parse(roomCode,System.Globalization.CultureInfo.InvariantCulture);
        Span<byte> bytes=stackalloc byte[9];var remaining=body;
        for(int i=8;i>=0;i--){bytes[i]=(byte)(remaining&255);remaining>>=8;}
        UInt128 value=(body<<8)|Checksum(bytes);var result=new StringBuilder(19);
        for(int i=15;i>=0;i--){if(i<15&&(i+1)%4==0)result.Append('-');result.Append(Alphabet[(int)((value>>(i*5))&31)]);}
        return result.ToString();
    }
    public static CompactDirectCode Import(string? text)
    {
        if(text is null||text.Length>MaximumTextLength)throw new FormatException("请输入主机生成的 16 位直连码");
        UInt128 value=0;int symbols=0;
        foreach(char raw in text){
            if(raw=='-'||char.IsWhiteSpace(raw))continue;
            char c=char.ToUpperInvariant(raw);if(c=='O')c='0';else if(c is 'I' or 'L')c='1';
            int digit=Alphabet.IndexOf(c);if(digit<0||++symbols>Symbols)throw new FormatException("直连码应为 16 位字母数字，不区分大小写");
            value=(value<<5)|(uint)digit;
        }
        if(symbols!=Symbols)throw new FormatException("请输入完整的 16 位直连码");
        byte checksum=(byte)(value&255);UInt128 body=value>>8,remaining=body;Span<byte> bytes=stackalloc byte[9];
        for(int i=8;i>=0;i--){bytes[i]=(byte)(remaining&255);remaining>>=8;}
        if(Checksum(bytes)!=checksum)throw new FormatException("直连码校验失败，请检查是否输错或缺少字符");
        int header=(int)(body>>68);if((header>>1)!=Version)throw new FormatException("直连码版本不受支持，请将两端更新到同一版本");
        uint number=(uint)((body>>36)&uint.MaxValue);int port=(int)((body>>20)&65535),room=(int)(body&0xfffff);
        if(room>=1_000_000||port==0)throw new FormatException("直连码的入口或会话无效");
        string endpoint=$"{number>>24}.{(number>>16)&255}.{(number>>8)&255}.{number&255}:{port}";
        ExistingEntryResolver.ParseEndpoint(endpoint);
        return new(endpoint,(header&1)==0?"faketcp":"udp",room.ToString("D6",System.Globalization.CultureInfo.InvariantCulture));
    }
}
