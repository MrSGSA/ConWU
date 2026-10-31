namespace StreamLink.Core;

// Per mapping, bounded by its configured list. A healthy helper never rotates.
// Failed reflectors cool down; this does not create a new server dependency.
internal sealed class TcpHelperRecovery(TimeProvider? time = null)
{
    readonly TimeProvider clock = time ?? TimeProvider.System;
    readonly Dictionary<string, long> failed = new(StringComparer.OrdinalIgnoreCase);
    public void Failed(string server)
    {
        if (failed.Count >= 256 && !failed.ContainsKey(server)) failed.Remove(failed.MinBy(x => x.Value).Key);
        failed[server] = clock.GetTimestamp();
    }
    public string[] Candidates(IEnumerable<string> configured, string preferred)
    {
        var choices = configured.Distinct(StringComparer.OrdinalIgnoreCase).Take(256).ToArray();
        foreach (var item in failed.Where(x => clock.GetElapsedTime(x.Value).TotalMinutes >= 5).ToArray()) failed.Remove(item.Key);
        var ready = choices.Where(s => !failed.ContainsKey(s)).OrderByDescending(s => s.Equals(preferred, StringComparison.OrdinalIgnoreCase)).ToArray();
        // A user may deliberately configure only one server. Do not invent a
        // public fallback or turn a temporary outage into permanent refusal.
        return ready.Length > 0 ? ready : choices.OrderBy(s => failed.GetValueOrDefault(s)).ToArray();
    }
}
