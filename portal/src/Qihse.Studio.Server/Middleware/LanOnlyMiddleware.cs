using System.Net;

namespace Qihse.Studio.Server.Middleware;

/// <summary>
/// Enforces strict LAN-only and loopback access for QIHSE Studio by default.
/// Rejects non-RFC1918 public WAN connections with HTTP 403 Forbidden.
/// </summary>
public class LanOnlyMiddleware
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
        if (_lanOnlyEnabled)
        {
            var remoteIp = context.Connection.RemoteIpAddress;
            if (remoteIp == null)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
            {
                if (remoteIp.IsIPv4MappedToIPv6)
                {
                    remoteIp = remoteIp.MapToIPv4();
                }

                if (!IsPrivateOrLoopback(remoteIp) ||
                    (!IPAddress.IsLoopback(remoteIp) && !context.Request.IsHttps))
                {
                    _logger.LogWarning("Blocked non-LAN connection attempt from {RemoteIp}", remoteIp);
                    context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"access denied\"}");
                    return;
                }
            }
        }

        await _next(context);
    }

    public static bool IsPrivateOrLoopback(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = ip.GetAddressBytes();
            // 10.0.0.0/8
            if (bytes[0] == 10) return true;
            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            // 169.254.0.0/16 Link-local
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            // 127.0.0.0/8 Loopback
            if (bytes[0] == 127) return true;
        }
        else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal) return true;
        }

        return false;
    }
}
