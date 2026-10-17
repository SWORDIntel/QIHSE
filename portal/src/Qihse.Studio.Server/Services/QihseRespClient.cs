using System.Net.Sockets;
using System.Text;

namespace Qihse.Studio.Server.Services;

public class QihseRespClient : IDisposable
{
    private readonly string _host;
    private readonly int _port;
    private readonly string? _password;
    private TcpClient? _tcpClient;
    private NetworkStream? _stream;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public string Host => _host;
    public int Port => _port;
    public bool IsConnected => _tcpClient != null && _tcpClient.Connected;

    public QihseRespClient(string host, int port, string? password = null)
    {
        _host = host;
        _port = port;
        _password = password;
    }

    public async Task<bool> ConnectAsync(CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            if (IsConnected) return true;

            _tcpClient?.Dispose();
            _tcpClient = new TcpClient();
            await _tcpClient.ConnectAsync(_host, _port, ct);
            _stream = _tcpClient.GetStream();

            if (!string.IsNullOrEmpty(_password))
            {
                var authResp = await SendCommandInternalAsync(new[] { "AUTH", _password }, ct);
                if (authResp.StartsWith("-"))
                {
                    return false;
                }
            }

            return true;
        }
        catch
        {
            _tcpClient?.Dispose();
            _tcpClient = null;
            _stream = null;
            return false;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<string> SendCommandAsync(string[] args, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            if (!IsConnected)
            {
                var ok = await ConnectAsync(ct);
                if (!ok) return "-ERR connection failed";
            }

            return await SendCommandInternalAsync(args, ct);
        }
        catch (Exception ex)
        {
            _tcpClient?.Dispose();
            _tcpClient = null;
            _stream = null;
            return $"-ERR {ex.Message}";
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<string> SendCommandInternalAsync(string[] args, CancellationToken ct)
    {
        if (_stream == null) throw new InvalidOperationException("Not connected");

        // Format RESP Array: *<len>\r\n$<arg0_len>\r\n<arg0>\r\n...
        var sb = new StringBuilder();
        sb.Append($"*{args.Length}\r\n");
        foreach (var arg in args)
        {
            var bytes = Encoding.UTF8.GetByteCount(arg);
            sb.Append($"${bytes}\r\n{arg}\r\n");
        }

        var writeBuf = Encoding.UTF8.GetBytes(sb.ToString());
        await _stream.WriteAsync(writeBuf, ct);
        await _stream.FlushAsync(ct);

        // Read Response
        return await ReadRespAsync(_stream, ct);
    }

    private static async Task<string> ReadRespAsync(NetworkStream stream, CancellationToken ct)
    {
        var firstByte = stream.ReadByte();
        if (firstByte == -1) return "-ERR EOF";

        char type = (char)firstByte;
        var line = await ReadLineAsync(stream, ct);

        switch (type)
        {
            case '+': // Simple String
                return line;
            case '-': // Error
                return $"-{line}";
            case ':': // Integer
                return line;
            case '$': // Bulk String
                if (int.TryParse(line, out int len))
                {
                    if (len == -1) return "(nil)";
                    var bulkBytes = new byte[len];
                    int totalRead = 0;
                    while (totalRead < len)
                    {
                        int read = await stream.ReadAsync(bulkBytes.AsMemory(totalRead, len - totalRead), ct);
                        if (read == 0) break;
                        totalRead += read;
                    }
                    // Discard trailing \r\n
                    stream.ReadByte();
                    stream.ReadByte();
                    return Encoding.UTF8.GetString(bulkBytes);
                }
                return line;
            case '*': // Array
                if (int.TryParse(line, out int arrayLen))
                {
                    if (arrayLen == -1) return "(nil)";
                    var items = new List<string>();
                    for (int i = 0; i < arrayLen; i++)
                    {
                        items.Add(await ReadRespAsync(stream, ct));
                    }
                    return string.Join("\n", items);
                }
                return line;
            default:
                return $"{type}{line}";
        }
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream, CancellationToken ct)
    {
        var sb = new StringBuilder();
        while (true)
        {
            var b = stream.ReadByte();
            if (b == -1) break;
            if (b == '\r')
            {
                var next = stream.ReadByte();
                if (next == '\n' || next == -1) break;
                sb.Append((char)b);
                sb.Append((char)next);
            }
            else
            {
                sb.Append((char)b);
            }
        }
        return sb.ToString();
    }

    public void Dispose()
    {
        _stream?.Dispose();
        _tcpClient?.Dispose();
        _lock.Dispose();
    }
}
