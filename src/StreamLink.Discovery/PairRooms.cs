using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.Discovery;

public sealed class PairRooms(TimeProvider? time = null)
{
    sealed class Room
    {
        public string Id = Guid.NewGuid().ToString("N"), Code = "", Owner = NewToken(), Guest = "", HostCommit = "", HostName = "", Candidate = "", GuestCommit = "", GuestName = "", HostPublic = "", GuestPublic = "", Cipher = "";
        public long Expires = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        public bool Approved;
        public PairRoomState State() => new(Candidate, GuestCommit, GuestName, HostPublic, GuestPublic, Cipher, Approved, Expires);
    }
    readonly Dictionary<string, Room> rooms = new();
    readonly object gate = new();
    readonly TimeProvider clock = time ?? TimeProvider.System;
    static string NewToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    static bool NameOk(string name) => name != null && name.Length is > 0 and <= 64 && !name.Any(char.IsControl);
    static bool Authorized(HttpContext context, string expected)
    {
        string value = context.Request.Headers.Authorization.ToString();
        return expected.Length == 64 && value.Length == 71 && value.StartsWith("Bearer ", StringComparison.Ordinal) && CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(value[7..]), System.Text.Encoding.ASCII.GetBytes(expected));
    }
    void Prune() { long now = clock.GetUtcNow().ToUnixTimeSeconds(); foreach (var id in rooms.Where(p => p.Value.Expires <= now).Select(p => p.Key).ToArray()) rooms.Remove(id); }
    public IResult Create(PairRoomCreate input)
    {
        if (!PairKeyExchange.ValidCommitment(input.Commitment) || !NameOk(input.Name)) return Results.BadRequest();
        lock (gate) {
            Prune(); if (rooms.Count >= 128) return Results.StatusCode(503);
            var room = new Room { HostCommit = input.Commitment, HostName = input.Name, Expires = clock.GetUtcNow().AddMinutes(5).ToUnixTimeSeconds() };
            do { room.Code = RandomNumberGenerator.GetInt32(1_000_000).ToString("D6"); } while (rooms.Values.Any(r => r.Code == room.Code));
            rooms.Add(room.Id, room);
            return Results.Json(new PairRoomTicket(room.Id, room.Code, room.Owner, room.HostCommit, room.HostName, room.Expires));
        }
    }
    public IResult Join(PairRoomJoin input)
    {
        if (!PairKeyExchange.ValidCommitment(input.Commitment) || !NameOk(input.Name) || input.Code is null || input.Code.Length != 6 || input.Code.Any(c => c is < '0' or > '9')) return Results.BadRequest();
        lock (gate) {
            Prune(); var room = rooms.Values.FirstOrDefault(r => r.Code == input.Code && !r.Approved);
            if (room == null) return Results.NotFound();
            if (room.Candidate.Length > 0) return Results.Conflict();
            room.Candidate = Guid.NewGuid().ToString("N"); room.Guest = NewToken(); room.GuestCommit = input.Commitment; room.GuestName = input.Name;
            return Results.Json(new PairRoomTicket(room.Id, "", room.Guest, room.HostCommit, room.HostName, room.Expires, room.Candidate));
        }
    }
    public IResult Exchange(HttpContext context, string id, bool owner, PairRoomReveal? reveal = null, PairRoomApproval? approve = null, bool close = false)
    {
        lock (gate) {
            Prune(); if (!rooms.TryGetValue(id, out var room)) return Results.NotFound();
            if (!Authorized(context, owner ? room.Owner : room.Guest)) return Results.Unauthorized();
            if (close) { rooms.Remove(id); return Results.Json(new { closed = true }); }
            if (reveal != null) {
                if (room.Candidate.Length == 0 || (!owner && room.HostPublic.Length == 0) || room.Approved) return Results.Conflict();
                try { PairKeyExchange.ValidatePublic(reveal.PublicKey, owner ? room.HostCommit : room.GuestCommit); } catch { return Results.BadRequest(); }
                if (owner) room.HostPublic = reveal.PublicKey; else room.GuestPublic = reveal.PublicKey;
            }
            if (approve != null) {
                if (!owner || room.Approved || room.HostPublic.Length == 0 || room.GuestPublic.Length == 0 || approve.Candidate != room.Candidate || approve.Ciphertext is null || approve.Ciphertext.Length is < 40 or > 6000) return Results.Conflict();
                try { Convert.FromBase64String(approve.Ciphertext); } catch { return Results.BadRequest(); }
                room.Approved = true; room.Code = ""; room.Cipher = approve.Ciphertext;
            }
            return Results.Json(room.State());
        }
    }
}
