using StreamLink.Core;

namespace StreamLink.Discovery;

// Only authenticated endpoint activity creates a device in this bounded view.
public sealed class CoordinatorClients(TimeProvider? time = null)
{
    sealed record Activity(string Device,string Name,string Scope,string Phase,DateTimeOffset LastSeen,long Tick,long Order);
    readonly object gate = new();
    readonly Dictionary<(string Device,string Scope),Activity> activities = [];
    readonly TimeProvider clock = time ?? TimeProvider.System;
    long sequence;
    void Prune()
    {
        long now = clock.GetTimestamp();
        foreach (var key in activities.Where(pair=>clock.GetElapsedTime(pair.Value.Tick,now)>=TimeSpan.FromMinutes(3)).Select(pair=>pair.Key).ToArray())
            activities.Remove(key);
    }
    public void Observe(string device,string name,string scope,string phase)
    {
        lock (gate) {
            Prune();
            var key = (device,scope);
            if (name.Length == 0)
                name = activities.Values.Where(activity=>activity.Device==device&&activity.Name.Length>0).MaxBy(activity=>activity.Order)?.Name ?? "";
            if (activities.Count >= 512 && !activities.ContainsKey(key))
                activities.Remove(activities.MinBy(pair=>pair.Value.Order).Key);
            activities[key] = new(device,name,scope,phase,clock.GetUtcNow(),clock.GetTimestamp(),++sequence);
        }
    }
    public void RemoveScope(string scope)
    {
        lock (gate) foreach (var key in activities.Keys.Where(key=>key.Scope==scope).ToArray()) activities.Remove(key);
    }
    public CoordinatorClientDto[] Snapshot()
    {
        lock (gate) {
            Prune();
            return activities.Values.GroupBy(activity=>activity.Device,StringComparer.Ordinal)
                .Select(group=>{
                    var latest=group.MaxBy(activity=>activity.Order)!;
                    string name=group.Where(activity=>activity.Name.Length>0).MaxBy(activity=>activity.Order)?.Name ?? "设备 " + group.Key[..Math.Min(8,group.Key.Length)];
                    return new CoordinatorClientDto(group.Key,name,latest.Phase,group.Where(activity=>!activity.Scope.StartsWith("pair:",StringComparison.Ordinal)).Select(activity=>activity.Scope).Distinct(StringComparer.Ordinal).Count(),latest.LastSeen);
                }).OrderByDescending(client=>client.LastSeen).Take(128).ToArray();
        }
    }
}
