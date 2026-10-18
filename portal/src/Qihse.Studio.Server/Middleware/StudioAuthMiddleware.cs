using System.Security.Cryptography;
using System.Text;

namespace Qihse.Studio.Server.Middleware;

/// <summary>Fail-closed bearer authorization for Studio API and SignalR.</summary>
public sealed class StudioAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly byte[] _expectedHash;

    public StudioAuthMiddleware(RequestDelegate next, IConfiguration config)
    {
        _next = next;
        var token = Environment.GetEnvironmentVariable("QIHSE_STUDIO_API_TOKEN")
                    ?? config["Studio:ApiToken"];
        if (string.IsNullOrWhiteSpace(token) || token.Length < 32)
            throw new InvalidOperationException("QIHSE_STUDIO_API_TOKEN must contain at least 32 characters.");
        _expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path;
        if (!path.StartsWithSegments("/api") && !path.StartsWithSegments("/hub"))
        {
            await _next(context);
            return;
        }
        string? supplied = null;
        var header = context.Request.Headers.Authorization.ToString();
        if (header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            supplied = header.Substring(7);
        else if (path.StartsWithSegments("/hub/telemetry") &&
                 context.Request.Query.TryGetValue("access_token", out var query))
            supplied = query.ToString(); // Browser WebSocket clients cannot set Authorization.

        if (string.IsNullOrEmpty(supplied) || supplied.Length > 4096 ||
            !CryptographicOperations.FixedTimeEquals(
                _expectedHash, SHA256.HashData(Encoding.UTF8.GetBytes(supplied))))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.CacheControl = "no-store";
            return;
        }
        context.Response.Headers.CacheControl = "no-store";
        await _next(context);
    }
}
