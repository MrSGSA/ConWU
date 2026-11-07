using System.Text.RegularExpressions;

namespace StreamLink.Core;
public static class SensitiveText
{
    public static string Redact(string text,DeviceProfile profile)
    {
        var credentials=new HashSet<string>(StringComparer.Ordinal);
        void Pair(Pairing? pair){if(pair==null)return;credentials.Add(pair.Secret);string raw=new Invitation(1,pair.Network,pair.Secret,"",pair.Mode,"",0).RawKey;credentials.Add(raw);credentials.Add(raw.ToUpperInvariant());}
        Pair(profile.Pair);Pair(profile.Mesh?.Pair);
        credentials.Add(profile.CloudflareDdnsToken);
        credentials.Add(profile.NodeSigningPrivate);
        foreach(var entry in profile.ExistingEntries.Concat(profile.JoinedEntrySources))
            if(Uri.TryCreate(entry.Source,UriKind.Absolute,out var source)&&source.Scheme=="https"&&source.Query.Length>0)credentials.Add(entry.Source);
        if(profile.Mesh is{} mesh){credentials.Add(mesh.OwnerPrivate);credentials.Add(mesh.SigningPrivate);credentials.Add(mesh.ExchangePrivate);}
        if(profile.PendingMembership is {} pending){if(pending.Ciphertext.Length<=text.Length)credentials.Add(pending.Ciphertext);if(pending.Room!=null)credentials.Add(pending.Room.Token);}
        if(profile.RejoinCredential is {} rejoin)credentials.Add(rejoin.SigningPrivate);
        foreach(var credential in credentials.Where(c=>c.Length>=16).OrderByDescending(c=>c.Length))text=text.Replace(credential,"[凭据已隐藏]",StringComparison.Ordinal);
        // Invitations intentionally carry credentials; strip the entire token,
        // even if it belongs to a different/currently retired profile.
        try{return Regex.Replace(text,@"\bSL[0-9]+\.[A-Za-z0-9+/=_-]{16,}","[邀请已隐藏]",RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(100));}catch(RegexMatchTimeoutException){return "[日志脱敏超时，原文未输出]";}
    }
}
