using System.Security.Cryptography;
using System.Text;

namespace Qihse.Studio.Server.Middleware;

/// <summary>Bearer authorization for Studio API and SignalR, allowing LAN telemetry reading.</summary>
public sealed class StudioAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly byte[] _expectedHash;

    public StudioAuthMiddleware(RequestDelegate next)
    {
        _next = next;
        var token = Environment.GetEnvironmentVariable("QIHSE_STUDIO_API_TOKEN");
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

        // Check if connection is from private LAN or loopback
        var remoteIp = context.Connection.RemoteIpAddress;
        if (remoteIp != null && remoteIp.IsIPv4MappedToIPv6)
            remoteIp = remoteIp.MapToIPv4();

        bool isLanOrLoopback = remoteIp != null && LanOnlyMiddleware.IsPrivateOrLoopback(remoteIp);

        string? supplied = null;
        var header = context.Request.Headers.Authorization.ToString();
        if (header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            supplied = header.Substring(7);
        else if (path.StartsWithSegments("/hub/telemetry") &&
                 context.Request.Query.TryGetValue("access_token", out var query))
            supplied = query.ToString(); // Browser WebSocket clients cannot set Authorization.

        // If valid token is supplied, authorize request
        if (!string.IsNullOrEmpty(supplied))
        {
            if (supplied.Length <= 8192 &&
                CryptographicOperations.FixedTimeEquals(
                    _expectedHash, SHA256.HashData(Encoding.UTF8.GetBytes(supplied))))
            {
                context.Response.Headers.CacheControl = "no-store";
                await _next(context);
                return;
            }
        }

        // Allow telemetry inspection and SignalR streaming from trusted LAN/loopback
        if (isLanOrLoopback && (HttpMethods.IsGet(context.Request.Method) || path.StartsWithSegments("/hub")))
        {
            context.Response.Headers.CacheControl = "no-store";
            await _next(context);
            return;
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.CacheControl = "no-store";
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync("{\"error\":\"unauthorized\",\"message\":\"Valid QIHSE_STUDIO_API_TOKEN bearer token required.\"}");
    }
}
