using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace StreamLink.Core;

internal sealed record TxtRecoveryAnswer(string Resolver, string[] Documents);

// Used only while recovering an explicitly configured public TXT entry.
// HTTPS protects this alternate discovery path; it never authorizes a member.
internal sealed class DnsOverHttpsTextLookup : IDisposable
{
    static readonly (string Name, Uri Uri)[] providers = [
        ("AliDNS", new("https://dns.alidns.com/dns-query")),
        ("Tencent", new("https://doh.pub/dns-query")),
        ("Cloudflare", new("https://cloudflare-dns.com/dns-query")),
    ];
    readonly HttpClient client;

    internal DnsOverHttpsTextLookup(HttpMessageHandler? handler = null)
    {
        client = new(handler ?? new SocketsHttpHandler {
            UseProxy = false, AllowAutoRedirect = false, UseCookies = false,
            MaxConnectionsPerServer = 2, ConnectTimeout = TimeSpan.FromSeconds(2),
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2)
        }) { Timeout = Timeout.InfiniteTimeSpan };
    }

    internal static bool PublicName(string host)
    {
        host = host.TrimEnd('.');
        if (host.Length is < 3 or > 253 || !host.Contains('.') || IPAddress.TryParse(host, out _)) return false;
        if (host.Split('.').Any(p => p.Length is < 1 or > 63 || p.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')))) return false;
        return !new[] { ".localhost", ".local", ".internal", ".lan", ".home", ".test", ".invalid", ".example", ".arpa" }
            .Any(s => host.EndsWith(s, StringComparison.OrdinalIgnoreCase));
    }

    internal async Task<TxtRecoveryAnswer[]> Query(string host, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!PublicName(host)) return [];
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(3000);
        var answers = await Task.WhenAll(providers.Select(p => QueryOne(p.Name, p.Uri, host.TrimEnd('.'), deadline.Token, token)));
        return answers.OfType<TxtRecoveryAnswer>().ToArray();
    }

    async Task<TxtRecoveryAnswer?> QueryOne(string name, Uri uri, string host, CancellationToken deadline, CancellationToken caller)
    {
        try {
            ushort id = (ushort)RandomNumberGenerator.GetInt32(65536);
            byte[] question = host.Split('.').SelectMany(p => new[] { (byte)p.Length }.Concat(Encoding.ASCII.GetBytes(p)))
                .Concat(new byte[] { 0, 0, 16, 0, 1 }).ToArray();
            byte[] wire = new byte[12 + question.Length];
            BinaryPrimitives.WriteUInt16BigEndian(wire, id); wire[2] = 1; wire[5] = 1; question.CopyTo(wire, 12);
            using var request = new HttpRequestMessage(HttpMethod.Post, uri) { Content = new ByteArrayContent(wire) };
            request.Content.Headers.ContentType = new("application/dns-message");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
            request.Headers.CacheControl = new() { NoCache = true, NoStore = true };
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline);
            if (!response.IsSuccessStatusCode || response.Content.Headers.ContentType?.MediaType != "application/dns-message" ||
                response.Content.Headers.ContentLength > ExistingEntryResolver.MaximumBody) return null;
            using var stream = await response.Content.ReadAsStreamAsync(deadline);
            byte[] data = new byte[ExistingEntryResolver.MaximumBody + 1]; int count = 0, read;
            while (count < data.Length && (read = await stream.ReadAsync(data.AsMemory(count), deadline)) > 0) count += read;
            if (count > ExistingEntryResolver.MaximumBody) return null;
            return new(name, DnsTextLookup.Parse(data.AsSpan(0, count), id, question));
        } catch (Exception ex) when (!caller.IsCancellationRequested && ex is HttpRequestException or IOException or OperationCanceledException or FormatException) {
            // Provider responses and URLs are never echoed into product logs.
            return null;
        }
    }

    public void Dispose() => client.Dispose();
}
