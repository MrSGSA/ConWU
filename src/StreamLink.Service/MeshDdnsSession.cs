using StreamLink.Core;

namespace StreamLink.Service;

// Polled by the runner without awaiting network IO. DNS failures do not stop
// packet forwarding, rebuild adapters, or change the selected transport mode.
internal sealed class MeshDdnsSession : IAsyncDisposable
{
    readonly CloudflareDdnsClient writer;
    readonly Func<string, string, MeshMember, string, CancellationToken, Task<DdnsAddressRecord?>> read;
    readonly CancellationToken stop;
    readonly Func<long> utcNow;
    sealed record VerifiedRecord(DdnsAddressRecord Record, string SigningKey);
    readonly Dictionary<int, VerifiedRecord> cache = [];
    // Retain the watermark even after the accepted record expires, so an
    // older record with a longer lifetime cannot be reintroduced in-session.
    readonly Dictionary<int, VerifiedRecord> seen = [];
    CloudflareDdnsSettings settings = new();
    string credential = "", sourceKey = "", writingSources = "", membersKey = "", readingMembers = "", identity = "";
    int generation, writeGeneration, readGeneration, failures;
    long nextWrite, nextRead, lastWrite, retryAfter, publishedAt, checkedAt, lastIssued;
    Task? writing;
    Task<(MeshMember Member, DdnsAddressRecord? Record, string Error)[]>? reading;
    CancellationTokenSource? writeStop, readStop;
    string publishState = "未启用", readState = "未启用", recordName = "";
    public CloudflareDdnsStatus Status { get; private set; } = new("未启用", "", "");

    public MeshDdnsSession(CancellationToken stop, CloudflareDdnsClient? writer = null,
        Func<string, string, MeshMember, string, CancellationToken, Task<DdnsAddressRecord?>>? read = null, Func<long>? utcNow = null) {
        this.stop = stop; this.writer = writer ?? new(); this.read = read ?? DdnsAddressRecords.Read;
        this.utcNow = utcNow ?? (() => DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    public void Tick(CloudflareDdnsSettings desired, string token, MeshProfile mesh, string mode, string[] endpoints, long now)
    {
        string currentIdentity = mesh.Pair.Network + "/" + mesh.Self.Device + "/" + mode;
        if (settings != desired || credential != token || identity != currentIdentity) {
            bool changedTrust = identity != currentIdentity || !string.Equals(settings.Domain, desired.Domain, StringComparison.OrdinalIgnoreCase);
            generation++; writeStop?.Cancel(); readStop?.Cancel(); settings = desired; credential = token;
            identity = currentIdentity;
            if (changedTrust) { cache.Clear(); seen.Clear(); }
            if (!desired.Enabled) cache.Clear();
            sourceKey = membersKey = ""; nextRead = nextWrite = 0; lastWrite = retryAfter = 0; failures = 0; publishedAt = checkedAt = 0;
            publishState = desired.Publish ? "等待发布本机入口" : "仅读取，不发布本机入口"; readState = "等待查询成员入口";
        }
        long utc = utcNow();
        var members = mesh.Directory?.Members.Where(m => m.Slot != mesh.Self.Slot).ToArray() ?? [];
        var bySlot = members.ToDictionary(m => m.Slot);
        string memberIds = string.Join('|', members.OrderBy(m => m.Slot).Select(m => $"{m.Slot}:{m.Device}:{m.SigningKey}"));
        var publishable = endpoints.Where(DdnsAddressRecords.PublicEndpoint).Distinct().Order(StringComparer.Ordinal).Take(4).ToArray();
        string sources = string.Join('|', publishable) + "/" + mode;
        foreach (int slot in cache.Keys.ToArray()) {
            var member = bySlot.GetValueOrDefault(slot);
            if (member == null || !StillTrusted(cache[slot], mesh, member, mode, utc)) cache.Remove(slot);
        }
        foreach (int slot in seen.Keys.ToArray())
            if (!bySlot.TryGetValue(slot, out var member) || seen[slot].Record.Device != member.Device || seen[slot].SigningKey != member.SigningKey) seen.Remove(slot);
        if (writing?.IsCompleted == true) {
            try { writing.GetAwaiter().GetResult(); if (writeGeneration == generation) {
                publishedAt = utc; failures = 0; retryAfter = 0;
                publishState = "Cloudflare 已确认发布；DNS 缓存仍可能短暂保留旧记录";
                // A write may finish after the listener/address has changed.
                // Do not let that older completion defer the new publication.
                nextWrite = writingSources == sources ? now + settings.RefreshSeconds * 1000L : Math.Max(now, lastWrite + 15000);
            } }
            catch (Exception ex) when (!stop.IsCancellationRequested) {
                if (writeGeneration == generation) {
                    publishState = ex is CloudflareDdnsException or FormatException ? ex.Message : "DDNS 发布未完成，已保留连接并安排重试";
                    retryAfter = now + Math.Max(ex is CloudflareDdnsException known ? known.RetrySeconds * 1000L : 0, Math.Min(600000, 30000L << Math.Min(failures++, 4)));
                    nextWrite = retryAfter;
                }
            } finally { writing = null; writeStop?.Dispose(); writeStop = null; }
        }
        if (reading?.IsCompleted == true) {
            try {
                var responses = reading.GetAwaiter().GetResult();
                if (readGeneration == generation) {
                    int invalid = 0;
                    foreach (var item in responses) {
                        var current = bySlot.GetValueOrDefault(item.Member.Slot);
                        if (current == null || current.Device != item.Member.Device) continue;
                        if (item.Record is {} record && DdnsAddressRecords.Verify(record, settings.Domain, mesh.Pair.Network, current, mode, utc)) {
                            if (!seen.TryGetValue(current.Slot, out var prior) || record.IssuedAt > prior.Record.IssuedAt || record.IssuedAt == prior.Record.IssuedAt && record.Signature == prior.Record.Signature)
                                seen[current.Slot] = cache[current.Slot] = new(record, current.SigningKey);
                            else invalid++;
                        } else invalid++;
                    }
                    checkedAt = utc; readState = invalid == 0 ? "已核对成员地址签名；入口可用性仍由直连验证" : $"已查询成员入口；{invalid} 台设备尚无有效记录或查询未完成，保留未过期的已验证记录";
                    nextRead = readingMembers == memberIds ? now + settings.RefreshSeconds * 1000L : now;
                }
            } catch (Exception) when (!stop.IsCancellationRequested) { if (readGeneration == generation) { readState = "DDNS 查询暂未完成，保留未过期记录和健康连接"; nextRead = now + settings.RefreshSeconds * 1000L; } }
            finally { reading = null; readStop?.Dispose(); readStop = null; }
        }
        if (!settings.Enabled) { Status = new("未启用", "已停止发布，旧记录会按签名有效期过期", ""); return; }
        recordName = DdnsAddressRecords.Name(settings.Domain, mesh.Pair.Network, mesh.Self.Device);
        if (memberIds != membersKey) { membersKey = memberIds; nextRead = 0; }
        if (reading == null && now >= nextRead && members.Length > 0) {
            readStop = CancellationTokenSource.CreateLinkedTokenSource(stop); readStop.CancelAfter(TimeSpan.FromSeconds(25)); readGeneration = generation;
            readingMembers = memberIds;
            reading = ReadMembers(settings.Domain, mesh.Pair.Network, members, mode, readStop.Token);
            nextRead = now + settings.RefreshSeconds * 1000L;
        }
        if (members.Length == 0) readState = "当前网络暂无其他成员";
        if (sourceKey != sources) { sourceKey = sources; nextWrite = Math.Max(lastWrite == 0 ? 0 : lastWrite + 15000, retryAfter); }
        if (settings.Publish && credential.Length > 0 && writing == null && now >= nextWrite) {
            // Also distinguish consecutive writes across fast settings changes.
            long issued = Math.Max(utc, lastIssued + 1);
            if (issued > utc + 60) { nextWrite = now + 1000; return; }
            var record = DdnsAddressRecords.Create(mesh, settings.Domain, mode, publishable, issued, Math.Clamp(settings.RefreshSeconds * 3, 180, 1800));
            lastIssued = issued; writingSources = sources;
            writeStop = CancellationTokenSource.CreateLinkedTokenSource(stop); writeStop.CancelAfter(TimeSpan.FromSeconds(25)); writeGeneration = generation;
            writing = writer.Publish(settings, credential, record, writeStop.Token); lastWrite = now; nextWrite = now + settings.RefreshSeconds * 1000L;
            publishState = publishable.Length > 0 ? "正在发布本机入口" : "正在发布空入口：尚无已映射或已配置的公网接收地址";
        }
        string state = settings.Publish && publishable.Length == 0 ? "等待本机公网接收入口；DDNS 不会自动打开 NAT" : "已启用";
        Status = new(state, publishState, readState, recordName, publishedAt, checkedAt, cache.Values.Count(r => r.Record.Endpoints.Length > 0)) {
            EntryLink = settings.Publish ? DdnsEntryLink.Create(settings.Domain, mesh) : ""
        };
    }

    async Task<(MeshMember Member, DdnsAddressRecord? Record, string Error)[]> ReadMembers(string domain, string network, MeshMember[] members, string mode, CancellationToken token) {
        using var slots = new SemaphoreSlim(3);
        return await Task.WhenAll(members.Select(async member => {
            bool acquired = false;
            try {
                await slots.WaitAsync(token); acquired = true;
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(6000);
                return (Member: member, Record: await read(domain, network, member, mode, deadline.Token), Error: "");
            } catch (Exception) when (!stop.IsCancellationRequested) { return (Member: member, Record: (DdnsAddressRecord?)null, Error: "query-unavailable"); }
            finally { if (acquired) slots.Release(); }
        }));
    }
    bool StillTrusted(VerifiedRecord value, MeshProfile mesh, MeshMember member, string mode, long utc) => value.SigningKey == member.SigningKey &&
        value.Record.Device == member.Device && value.Record.Slot == member.Slot && value.Record.Network == mesh.Pair.Network &&
        value.Record.Domain == settings.Domain.ToLowerInvariant() && value.Record.Mode == mode && value.Record.ExpiresAt > utc && value.Record.IssuedAt <= utc + 60;
    public string[] ForMember(MeshProfile mesh, MeshMember member, string mode) => settings.Enabled && cache.TryGetValue(member.Slot, out var found) &&
        StillTrusted(found, mesh, member, mode, utcNow()) ? found.Record.Endpoints.ToArray() : [];
    public async ValueTask DisposeAsync() {
        writeStop?.Cancel(); readStop?.Cancel();
        try { if (writing != null) await writing; } catch { }
        try { if (reading != null) await reading; } catch { }
        writeStop?.Dispose(); readStop?.Dispose(); writer.Dispose(); cache.Clear(); seen.Clear(); credential = "";
    }
}
