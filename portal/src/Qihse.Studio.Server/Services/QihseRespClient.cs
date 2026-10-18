using System.Net;
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
            return await ConnectInternalAsync(ct);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<bool> ConnectInternalAsync(CancellationToken ct)
    {
        if (IsConnected) return true;

        // Plain RESP transport is not authenticated or confidential; do not send
        // operator credentials to remote peers until TLS/mTLS support exists.
        if (!IPAddress.TryParse(_host, out var remote) || !IPAddress.IsLoopback(remote))
            return false;

        _tcpClient?.Dispose();
        _tcpClient = new TcpClient();
        _tcpClient.SendTimeout = 2000;
        _tcpClient.ReceiveTimeout = 2000;

        try
        {
            await _tcpClient.ConnectAsync(_host, _port, ct);
            _stream = _tcpClient.GetStream();

            if (!string.IsNullOrEmpty(_password))
            {
                var authResp = await SendCommandInternalAsync(new[] { "AUTH", _password }, ct);
                if (authResp.StartsWith("-"))
                {
                    _tcpClient?.Dispose();
                    _tcpClient = null;
                    _stream = null;
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
    }

    public async Task<string> SendCommandAsync(string[] args, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(3));
            if (!IsConnected)
            {
                var ok = await ConnectInternalAsync(deadline.Token);
                if (!ok) return "-ERR connection failed";
            }

            return await SendCommandInternalAsync(args, deadline.Token);
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

        // RESP bulk arrays preserve argument boundaries and stop CR/LF injection.
        using var frame = new MemoryStream();
        frame.Write(Encoding.ASCII.GetBytes($"*{args.Length}\r\n"));
        foreach (var arg in args)
        {
            var bytes = Encoding.UTF8.GetBytes(arg);
            frame.Write(Encoding.ASCII.GetBytes($"${bytes.Length}\r\n"));
            frame.Write(bytes);
            frame.Write(new byte[] { 13, 10 });
        }
        await _stream.WriteAsync(frame.ToArray(), ct);
        await _stream.FlushAsync(ct);

        // Read Response
        return await ReadRespAsync(_stream, ct);
    }

    private static async Task<int> ReadByteAsync(NetworkStream stream, CancellationToken ct)
    {
        var buf = new byte[1];
        int read = await stream.ReadAsync(buf.AsMemory(0, 1), ct);
        return read == 0 ? -1 : buf[0];
    }

    private static async Task<string> ReadRespAsync(NetworkStream stream, CancellationToken ct,
        int depth = 0, int[]? budget = null)
    {
        budget ??= new[] { 4 * 1024 * 1024 };
        if (depth > 16) throw new InvalidDataException("RESP nesting exceeds limit");
        int first = await ReadByteAsync(stream, ct);
        if (first < 0) throw new EndOfStreamException("Truncated RESP reply");
        string line = await ReadLineAsync(stream, ct);
        if (line.Length > budget[0]) throw new InvalidDataException("RESP response too large");
        budget[0] -= line.Length;
        switch ((char)first)
        {
            case '+': return line;
            case '-': return "-" + line;
            case ':': return line;
            case '$':
                if (!int.TryParse(line, out int len) || len < -1 || len > 1048576)
                    throw new InvalidDataException("Invalid RESP bulk length");
                if (len == -1) return "(nil)";
                if (len > budget[0]) throw new InvalidDataException("RESP response budget exceeded");
                budget[0] -= len;
                var data = new byte[len];
                await stream.ReadExactlyAsync(data.AsMemory(), ct);
                if (await ReadByteAsync(stream, ct) != 13 || await ReadByteAsync(stream, ct) != 10)
                    throw new InvalidDataException("Invalid RESP bulk terminator");
                return Encoding.UTF8.GetString(data);
            case '*':
                if (!int.TryParse(line, out int count) || count < -1 || count > 4096)
                    throw new InvalidDataException("Invalid RESP array length");
                if (count == -1) return "(nil)";
                var items = new List<string>(count);
                for (int i = 0; i < count; i++)
                    items.Add(await ReadRespAsync(stream, ct, depth + 1, budget));
                return string.Join("\n", items);
            default:
                throw new InvalidDataException("Unknown RESP response prefix");
        }
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream, CancellationToken ct)
    {
        var bytes = new List<byte>();
        while (true)
        {
            int value = await ReadByteAsync(stream, ct);
            if (value < 0) throw new EndOfStreamException("Truncated RESP header");
            if (value == 13)
            {
                if (await ReadByteAsync(stream, ct) != 10)
                    throw new InvalidDataException("Malformed RESP CRLF");
                return Encoding.UTF8.GetString(bytes.ToArray());
            }
            if (value == 10 || bytes.Count >= 8192)
                throw new InvalidDataException("Malformed or oversized RESP header");
            bytes.Add((byte)value);
        }
    }

    public void Dispose()
    {
        _stream?.Dispose();
        _tcpClient?.Dispose();
        _lock.Dispose();
    }
}
