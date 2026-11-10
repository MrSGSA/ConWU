namespace StreamLink.Core;

public static class TransportModes
{
    public static bool Valid(string? mode)=>mode is "faketcp" or "udp" or "tcp" or "https";
    public static bool Stream(string? mode)=>mode is "tcp" or "https";
    public static PathPolicy FixedPolicy(string mode)=>mode switch{"faketcp"=>PathPolicy.FakeTcpOnly,"udp"=>PathPolicy.UdpOnly,"tcp"=>PathPolicy.TcpOnly,"https"=>PathPolicy.HttpsOnly,_=>throw new FormatException("传输方式无效")};
    public static string Policy(string mode)=>mode switch{"faketcp"=>"faketcp-only","udp"=>"udp-only","tcp"=>"tcp-only","https"=>"https-only",_=>throw new FormatException("传输方式无效")};
    public static string Mode(string policy)=>policy switch{"faketcp-only"=>"faketcp","udp-only"=>"udp","tcp-only"=>"tcp","https-only"=>"https",_=>throw new FormatException("请选择固定的传输方式")};
    public static string Label(string mode)=>mode switch{"tcp"=>"纯 TCP","https"=>"HTTPS","udp"=>"直接 UDP",_=>"FakeTCP＋HTTP"};
    public static TraversalProfile Carrier(string mode)=>Stream(mode)?TraversalProfile.LegacyExplicit:mode=="udp"?TraversalProfile.UdpDirect:TraversalProfile.FakeTcpHttpSo;
}
