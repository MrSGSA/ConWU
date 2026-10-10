using System.Diagnostics;

namespace StreamLink.Core;

// Monotonic stage timings contain no endpoints, configuration or pairing material.
public sealed class ConnectionTimeline(Action<string> log)
{
    readonly long started = Stopwatch.GetTimestamp();
    long previous = Stopwatch.GetTimestamp();
    public void Mark(string stage)
    {
        long now = Stopwatch.GetTimestamp();
        log($"连接计时：{stage}；阶段 {Stopwatch.GetElapsedTime(previous, now).TotalMilliseconds:F0} ms，累计 {Stopwatch.GetElapsedTime(started, now).TotalMilliseconds:F0} ms");
        previous = now;
    }
}
