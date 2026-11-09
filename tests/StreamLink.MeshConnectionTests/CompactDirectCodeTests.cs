using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static void CompactCodeTests()
    {
        const string vector="5JR0-E45A-840Y-4G12",alphabet="0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        Check(CompactDirectCode.Issue("203.0.113.10:42000","faketcp","123456")==vector,"compact code matches an independently calculated 80-bit network-order vector");
        var imported=CompactDirectCode.Import(vector);
        Check(imported==new CompactDirectCode("203.0.113.10:42000","faketcp","123456"),"sixteen symbols contain endpoint, protocol and room locator without a directory lookup");
        Check(CompactDirectCode.Import(" 5jrO e45a-84Oy-4gi2 ")==imported,"manual input accepts grouping, case and Crockford O/I aliases");
        foreach(string mode in new[]{"faketcp","udp"})foreach(string endpoint in new[]{"1.0.0.1:1","223.255.255.254:65535","10.171.139.1:44680"})foreach(string room in new[]{"000000","000001","999999"}){
            var code=CompactDirectCode.Issue(endpoint,mode,room);
            Check(code.Length==19&&code.Count(c=>c=='-')==3&&CompactDirectCode.Import(code)==new CompactDirectCode(endpoint,mode,room),"compact code round-trips address and port boundaries, protocol and leading-zero locators");
        }
        string plain=vector.Replace("-","");int mutations=0;
        for(int position=0;position<plain.Length;position++)foreach(char replacement in alphabet){
            if(replacement==plain[position])continue;
            var changed=plain.ToCharArray();changed[position]=replacement;
            bool rejected=false;try{CompactDirectCode.Import(new string(changed));}catch(FormatException){rejected=true;}
            if(!rejected)throw new Exception("single-symbol input error accepted at "+position);mutations++;
        }
        Check(mutations==496,"all 496 single-symbol substitutions are rejected by checksum or semantic validation");
        foreach(string text in new[]{"",plain[..15],plain+"0","SL6.expired-format",new string('U',16),new string('0',1000)}){
            bool rejected=false;try{CompactDirectCode.Import(text);}catch(FormatException){rejected=true;}Check(rejected,"malformed, incomplete and oversized codes are rejected before network activity");
        }
        foreach(string endpoint in new[]{"127.0.0.1:44680","0.0.0.0:1","224.0.0.1:1","169.254.1.1:1","203.0.113.1:0","host.example.com:44680"}){
            bool rejected=false;try{CompactDirectCode.Issue(endpoint,"faketcp","123456");}catch(FormatException){rejected=true;}Check(rejected,"unresolved or prohibited endpoints cannot be encoded as a ready entry");
        }
        Console.WriteLine($"PASS {checks} compact direct-code checks; checksum is not authentication");
    }
}
