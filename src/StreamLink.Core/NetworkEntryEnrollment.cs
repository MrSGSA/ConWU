using System.Text.Json;

namespace StreamLink.Core;

// Sent only inside the SAS-bound encrypted approval. The signed member
// enrollment remains authoritative; addresses are discovery hints only.
public sealed record NetworkEntryEnrollment(string Credential, ExistingEntry[] Entries)
{
    public ApprovedNetworkSettings? Settings {get;init;}
    const int MaximumEncoded=32000;
    public static string Encode(string credential, ExistingEntry[] entries,ApprovedNetworkSettings? settings=null)
    {
        ExistingEntryResolver.Validate(entries);
        if(entries.Any(e=>e.PeerSlot<=0))throw new FormatException("入网凭据中的入口需要明确的成员身份");
        string value="SL7."+Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new NetworkEntryEnrollment(credential,entries){Settings=settings}));
        if(value.Length>MaximumEncoded)throw new FormatException("入网凭据过长，请减少发布的入口来源");
        return value;
    }
    public static (MeshProfile Mesh,ExistingEntry[] Entries) Import(string value)
    {var result=ImportSettings(value);return(result.Mesh,result.Entries);}
    public static (MeshProfile Mesh,ExistingEntry[] Entries,ApprovedNetworkSettings? Settings) ImportSettings(string value)
    {
        if(value is null||!value.StartsWith("SL7.")||value.Length>MaximumEncoded)throw new FormatException("网络入口返回了无效入网凭据");
        NetworkEntryEnrollment envelope;
        try{envelope=JsonSerializer.Deserialize<NetworkEntryEnrollment>(Convert.FromBase64String(value[4..]))??throw new FormatException("入网凭据为空");}
        catch(JsonException){throw new FormatException("入网凭据格式无效");}
        if(envelope.Credential is not {Length:>0}||envelope.Entries is not {Length:<=12})throw new FormatException("入网凭据不完整");
        MeshProfile mesh;ExistingEntry[] inherited;
        if(envelope.Credential.StartsWith("SL5.")){var direct=DirectInvitation.Import(envelope.Credential);mesh=direct.Mesh;inherited=direct.Entries;}
        else{mesh=MeshIdentity.Import(envelope.Credential);inherited=[];}
        ExistingEntryResolver.Validate(envelope.Entries);
        if(envelope.Entries.Any(e=>e.PeerSlot<=0||mesh.Directory?.Members.Any(m=>m.Slot==e.PeerSlot)!=true))throw new FormatException("入网入口不属于获准网络成员");
        return(mesh,envelope.Entries.Concat(inherited).Distinct().ToArray(),envelope.Settings);
    }
}
