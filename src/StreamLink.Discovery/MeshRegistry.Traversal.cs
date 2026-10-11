using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.Discovery;

public sealed partial class MeshRegistry
{
    readonly record struct ControlKey(int From, int To, Guid FromBoot, Guid ToBoot);
    sealed record ControlState(MeshTraversalMessage Message, byte[] Fingerprint, long Received);
    sealed record SeenControl(byte[] Fingerprint, long Expires);
    long nextControlSweep;
    static void PruneControl(Feed feed)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        foreach (var key in feed.Control.Where(p => p.Value.Message.Expires <= now).Select(p => p.Key).ToArray()) feed.Control.Remove(key);
        foreach (var id in feed.ControlIds.Where(p => p.Value.Expires <= now).Select(p => p.Key).ToArray()) feed.ControlIds.Remove(id);
    }
    // Typed coordination state only: no arbitrary byte payload, stream, business
    // forwarding or user-supplied callback URL exists in this API.
    public IResult Traversal(HttpContext context, string network, MeshTraversalBatch input)
    {
        if (input?.Messages is not { Length: >= 1 and <= MeshTraversal.MaxBatch } messages || messages.Any(m => m == null) ||
            messages.Select(m => m.FromSlot).Distinct().Count() != 1 || messages.Select(m => m.ToSlot).Distinct().Count() != messages.Length ||
            messages.Select(m => m.MessageId).Distinct().Count() != messages.Length) return Results.BadRequest();
        lock (gate) {
            if (!networks.TryGetValue(network, out var registration)) return Results.StatusCode(412);
            if (!Equal(Auth(context), registration.AuthHash)) return Results.Unauthorized();
            var sender = registration.Directory.Members.FirstOrDefault(p => p.Slot == messages[0].FromSlot);
            if (sender == null) return Results.StatusCode(403);
            foreach (var message in messages) {
                var receiver = registration.Directory.Members.FirstOrDefault(p => p.Slot == message.ToSlot);
                if (receiver == null) return Results.StatusCode(403);
                try { MeshTraversal.Verify(network, sender, receiver, message); }
                catch (CryptographicException) { return Results.StatusCode(403); }
                catch (Exception ex) when (ex is FormatException or ArgumentException) { return Results.BadRequest(); }
            }
            if (!TakeRequest(network, sender.Slot)) return Results.StatusCode(429);
            var feed = State(network);
            long tick = Environment.TickCount64;
            if (tick >= nextControlSweep) {
                // Inactive networks must not retain expired replay tables while
                // new traffic moves to other networks. No background disk state.
                nextControlSweep = tick + 15000;
                foreach (var other in feeds.Values) PruneControl(other);
            } else PruneControl(feed);
            var pending = new List<(ControlKey Key, MeshTraversalMessage Message, byte[] Fingerprint)>();
            foreach (var message in messages) {
                var key = new ControlKey(message.FromSlot, message.ToSlot, message.FromBoot, message.ToBoot);
                byte[] fingerprint = MeshTraversal.Fingerprint(network, message);
                feed.Control.TryGetValue(key, out var current);
                if (feed.ControlIds.TryGetValue(message.MessageId, out var seen)) {
                    // An HTTP retry is idempotent ONLY while this exact state is
                    // current. Replaying a previously accepted Offer after Start
                    // must not roll the recipient back or wake a second attempt.
                    if (!CryptographicOperations.FixedTimeEquals(seen.Fingerprint, fingerprint) || current?.Message.MessageId != message.MessageId)
                        return Results.Conflict();
                    continue;
                }
                if (current != null && message.Sequence <= current.Message.Sequence) return Results.Conflict();
                pending.Add((key, message, fingerprint));
            }
            // Includes HTTP retry nonces, not just the visible latest state.
            // 512 network requests/min * at most 7 states/request fits this cap.
            if (feed.ControlIds.Count + pending.Count > 4096) return Results.StatusCode(429);
            foreach (var change in pending) {
                if (!feed.Control.ContainsKey(change.Key)) {
                    var siblings = feed.Control.Where(p => p.Key.From == change.Key.From && p.Key.To == change.Key.To).OrderBy(p => p.Value.Received).ToArray();
                    // Two boot pairs per directed member pair allow a restart
                    // overlap. Recipient still checks both current boot IDs.
                    if (siblings.Length >= 2) feed.Control.Remove(siblings[0].Key);
                }
                feed.Control[change.Key] = new(change.Message, change.Fingerprint, System.Diagnostics.Stopwatch.GetTimestamp());
                feed.ControlIds.Add(change.Message.MessageId, new(change.Fingerprint, change.Message.Expires));
                Changed(network, "traversal", change.Message.FromSlot, change.Message.ToSlot);
            }
            return Results.NoContent();
        }
    }
}
