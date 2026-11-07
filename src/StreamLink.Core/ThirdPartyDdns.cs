namespace StreamLink.Core;

// A separately owned TXT record is only an address hint. Third-party writers
// never overwrite ConWU's signed discovery record or receive member keys.
public static class ThirdPartyDdns
{
    public static string Name(string domain,string network,string device) =>
        "e-"+DdnsAddressRecords.Name(domain,network,device)[2..];
    public static string Source(string domain,string network,string device) =>
        "txt://"+Name(domain,network,device)+"#streamlink";
}
