using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.Discovery;

public sealed partial class MeshRegistry
{
    public IResult TcpObservation(HttpContext context, string network, TcpObserverRequest request, TcpSynObserver? observer)
    {
        if (request == null) return Results.BadRequest();
        lock (gate) {
            if (!networks.TryGetValue(network, out var registration)) return Results.StatusCode(412);
            if (!Equal(Auth(context), registration.AuthHash)) return Results.Unauthorized();
            var member = registration.Directory.Members.FirstOrDefault(m => m.Slot == request.Slot);
            if (member == null) return Results.StatusCode(403);
            try { TcpObserverProtocol.Verify(network, member, request); }
            catch (CryptographicException) { return Results.StatusCode(403); }
            catch (Exception ex) when (ex is ArgumentException or FormatException or NullReferenceException) { return Results.BadRequest(); }
            if (!TakeRequest(network, member.Slot)) return Results.StatusCode(429);
            if (observer == null) return Results.StatusCode(503);
            var result = observer.Request(network, request);
            return result.Reply == null ? Results.StatusCode(result.Status) : Results.Json(result.Reply);
        }
    }
}
