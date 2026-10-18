using System.Net;

namespace Qihse.Studio.Server.Middleware;

/// <summary>Reject remote plaintext traffic even if the optional LAN ACL is disabled.</summary>
public sealed class LanOnlyMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<LanOnlyMiddleware> _logger;
    private readonly bool _lanOnlyEnabled;

    public LanOnlyMiddleware(RequestDelegate next, ILogger<LanOnlyMiddleware> logger, IConfiguration config)
    {
        _next = next;
        _logger = logger;
        _lanOnlyEnabled = config.GetValue("Studio:LanOnly", true);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var remoteIp = context.Connection.RemoteIpAddress;
        if (remoteIp != null && remoteIp.IsIPv4MappedToIPv6)
            remoteIp = remoteIp.MapToIPv4();

        if (remoteIp == null ||
            (!IPAddress.IsLoopback(remoteIp) && !context.Request.IsHttps) ||
            (_lanOnlyEnabled && !IsPrivateOrLoopback(remoteIp)))
        {
            _logger.LogWarning("Rejected insecure or forbidden Studio transport from {RemoteIp}", remoteIp);
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.Headers.CacheControl = "no-store";
            await context.Response.WriteAsync("{\"error\":\"access denied\"}");
            return;
        }
        await _next(context);
    }

    public static bool IsPrivateOrLoopback(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = ip.GetAddressBytes();
            return bytes[0] == 10 ||
                   (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168) ||
                   (bytes[0] == 169 && bytes[1] == 254);
        }
        return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
               (ip.IsIPv6LinkLocal || ip.IsIPv6UniqueLocal);
    }
}
