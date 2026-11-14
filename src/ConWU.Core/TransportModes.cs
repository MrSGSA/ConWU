namespace StreamLink.Core;

public static class TransportModes
{
    public static bool Valid(string? mode)=>mode is "faketcp" or "udp" or "tcp" or "https" or "phantun" or "mimic" or "tcpraw";
    public static bool Stream(string? mode)=>mode is "tcp" or "https";
    public static bool PacketCarrier(string? mode)=>mode is "phantun" or "mimic" or "tcpraw";
    public static bool OutboundGuest(string? mode)=>Stream(mode)||PacketCarrier(mode);
    public static bool ManagedCandidates(string? mode)=>mode is "faketcp" or "udp";
    public static bool RequiresNewEnrollment(string before,string after)=>before!=after&&(OutboundGuest(before)||OutboundGuest(after));
    public static PathPolicy FixedPolicy(string mode)=>mode switch{"faketcp"=>PathPolicy.FakeTcpOnly,"udp"=>PathPolicy.UdpOnly,"tcp"=>PathPolicy.TcpOnly,"https"=>PathPolicy.HttpsOnly,"phantun"=>PathPolicy.PhantunOnly,"mimic"=>PathPolicy.MimicOnly,"tcpraw"=>PathPolicy.TcpRawOnly,_=>throw new FormatException("传输方式无效")};
    public static string Policy(string mode)=>Valid(mode)?mode+"-only":throw new FormatException("传输方式无效");
    public static string Mode(string policy)=>policy is {Length:>5}&&policy.EndsWith("-only",StringComparison.Ordinal)&&Valid(policy[..^5])?policy[..^5]:throw new FormatException("请选择固定的传输方式");
    public static string Label(string mode)=>mode switch{"tcp"=>"纯 TCP","https"=>"HTTPS","phantun"=>"Phantun","mimic"=>"Mimic","tcpraw"=>"TCPRAW","udp"=>"直接 UDP",_=>"FakeTCP＋HTTP"};
    public static TraversalProfile Carrier(string mode)=>OutboundGuest(mode)?TraversalProfile.LegacyExplicit:mode=="udp"?TraversalProfile.UdpDirect:TraversalProfile.FakeTcpHttpSo;
}
