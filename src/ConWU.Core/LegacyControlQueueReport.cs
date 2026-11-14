using System.Globalization;

namespace StreamLink.Core;

public sealed record LegacyControlQueueReport(long Sequence, long QueuedControls, long QueueRejected,
    long ParentDenied, long Expired, long StaleCapture, long PipeFailures)
{
    internal long[] Counters() => [QueuedControls, QueueRejected, ParentDenied, Expired, StaleCapture, PipeFailures];
    internal static bool TryParse(string line, Guid expected, out LegacyControlQueueReport? value)
    {
        value = null;
        if (line.Length > 512 || !line.StartsWith("SLGQ1 ", StringComparison.Ordinal)) return false;
        string[] fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length != 9 || fields[1] != expected.ToString("N")) return false;
        var numbers = new long[7];
        for (int i = 0; i < numbers.Length; i++) if (!long.TryParse(fields[i + 2], NumberStyles.None, CultureInfo.InvariantCulture, out numbers[i]) ||
            numbers[i] < 0 || numbers[i] > long.MaxValue / 16) return false;
        if (numbers[0] == 0) return false;
        value = new(numbers[0], numbers[1], numbers[2], numbers[3], numbers[4], numbers[5], numbers[6]); return true;
    }
}
