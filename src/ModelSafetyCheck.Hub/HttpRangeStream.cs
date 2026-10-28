using System.Net;

namespace ModelSafetyCheck.Hub;

/// <summary>The file exists but needs credentials (gated or private repo).</summary>
public sealed class AccessDeniedException(string message) : IOException(message);

/// <summary>
/// A read-only, seekable view of a remote file that fetches 1 MiB blocks with HTTP Range requests on
/// demand. Lets the GGUF parser read just the header of a multi-gigabyte model. Stops with an
/// <see cref="IOException"/> once <paramref name="budgetBytes"/> have been downloaded.
/// </summary>
public sealed class HttpRangeStream : Stream
{
    const int BlockSize = 1 << 20;

    readonly HttpClient _http;
    readonly Uri _url;
    readonly long _budget;
    readonly Dictionary<long, byte[]> _blocks = [];
    long _position;

    public HttpRangeStream(HttpClient http, Uri url, long budgetBytes)
    {
        _http = http;
        _url = url;
        _budget = budgetBytes;
        Length = FetchBlock(0, learnLength: true);
    }

    public long Downloaded { get; private set; }
    public override long Length { get; }
    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;

    public override long Position
    {
        get => _position;
        set => _position = value is >= 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        var total = 0;
        while (buffer.Length > 0 && _position < Length)
        {
            var index = _position / BlockSize;
            if (!_blocks.TryGetValue(index, out var block))
            {
                FetchBlock(index, learnLength: false);
                block = _blocks[index];
            }
            var within = (int)(_position - index * BlockSize);
            var n = Math.Min(buffer.Length, block.Length - within);
            if (n <= 0)
                break;
            block.AsSpan(within, n).CopyTo(buffer);
            buffer = buffer[n..];
            _position += n;
            total += n;
        }
        return total;
    }

    public override long Seek(long offset, SeekOrigin origin) => Position = origin switch
    {
        SeekOrigin.Begin => offset,
        SeekOrigin.Current => _position + offset,
        _ => Length + offset,
    };

    /// <summary>Fetches one block; on the first call also returns the total file length from Content-Range.</summary>
    long FetchBlock(long index, bool learnLength)
    {
        var start = index * BlockSize;
        var end = learnLength ? start + BlockSize - 1 : Math.Min(start + BlockSize, Length) - 1;
        if (Downloaded + (end - start + 1) > _budget)
            throw new IOException($"Download budget of {_budget / (1 << 20)} MiB reached before the header was fully read.");

        using var request = new HttpRequestMessage(HttpMethod.Get, _url);
        request.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(start, end);
        using var response = _http.Send(request, HttpCompletionOption.ResponseHeadersRead);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new AccessDeniedException($"Access denied ({(int)response.StatusCode}). The repo may be gated: set HF_TOKEN.");
        if (response.StatusCode != HttpStatusCode.PartialContent)
            throw new IOException($"Server did not honour the range request (HTTP {(int)response.StatusCode}).");

        using var body = response.Content.ReadAsStream();
        using var memory = new MemoryStream();
        body.CopyTo(memory);
        var bytes = memory.ToArray();
        Downloaded += bytes.Length;
        _blocks[index] = bytes;
        return learnLength ? response.Content.Headers.ContentRange?.Length ?? throw new IOException("Server did not report the file size.") : Length;
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
