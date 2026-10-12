using System.Diagnostics;
using System.Net;

namespace StreamLink.Core;

// A small cache per retained send resource. Port guesses to one IP do not
// create more records. Lookup runs outside the pacing lock; expiry refreshes
// OS evidence without touching network settings or creating probe sockets.
internal sealed class EgressRouteCache
{
    readonly object gate = new();
    readonly Dictionary<(IPAddress Source, IPAddress Target), (string Key, long At)> entries = [];
    readonly Func<IPAddress, IPAddress, string> lookup;
    public EgressRouteCache() : this(EgressRouteSnapshot.PacingKey) { }
    internal EgressRouteCache(Func<IPAddress, IPAddress, string> lookup) => this.lookup = lookup;
    public string Get(IPAddress source, IPAddress target)
    {
        lock (gate) {
            if (entries.TryGetValue((source, target), out var old) && Stopwatch.GetElapsedTime(old.At).TotalSeconds < 5) return old.Key;
        }
        string key = lookup(source, target);
        lock (gate) {
            if (entries.Count >= 32 && !entries.ContainsKey((source, target))) entries.Remove(entries.MinBy(e => e.Value.At).Key);
            entries[(source, target)] = (key, Stopwatch.GetTimestamp());
        }
        return key;
    }
}
