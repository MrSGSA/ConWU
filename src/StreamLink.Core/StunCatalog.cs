namespace StreamLink.Core;

public static class StunCatalog
{
    public const string Source = "https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_hosts_tcp.txt";
    public static string[] Parse(string text)
    {
        if (text.Length > 65536) throw new FormatException("STUN 列表过大");
        var values = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Select(v => v.Trim()).Where(v => v.Length > 0 && !v.StartsWith('#')).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        DeviceProfile.ValidateServers(values); return values;
    }
    public static string[] Snapshot()
    {
        using var stream = typeof(StunCatalog).Assembly.GetManifestResourceStream("StreamLink.Core.tcp-stun-snapshot.txt");
        if (stream == null) return [];
        using var reader = new StreamReader(stream); return Parse(reader.ReadToEnd());
    }
    public static async Task<string[]> Download(CancellationToken token)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15), MaxResponseContentBufferSize = 65536 };
        return Parse(await http.GetStringAsync(Source, token));
    }
}
