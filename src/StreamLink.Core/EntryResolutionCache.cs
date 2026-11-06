namespace StreamLink.Core;

public static class EntryResolutionCache
{
    public static EntryResolution Current(EntryResolution item, long now) => item.ExpiresAt > 0 && item.ExpiresAt <= now
        ? item with { Endpoints = [], Error = "入口已过期，等待来源更新", AllowCached = false } : item;
    public static EntryResolution Merge(EntryResolution result, EntryResolution? previous, long now) {
        result = Current(result, now);
        if (result.Error.Length == 0 || !result.AllowCached || previous == null) return result;
        previous = Current(previous, now);
        return previous.Endpoints.Length == 0 ? result : result with { Endpoints = previous.Endpoints, ExpiresAt = previous.ExpiresAt };
    }
}
