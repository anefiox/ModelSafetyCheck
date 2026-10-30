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
    readonly Lock _budgetLock = new();
    long _reserved;
    long _downloaded;

    // Hugging Face redirects every resolve request to a signed CDN URL; reusing it halves the round trips of ReadRange.
    volatile Uri? _resolved;
    readonly Dictionary<long, byte[]> _blocks = [];
    long _position;

    public HttpRangeStream(HttpClient http, Uri url, long budgetBytes)
    {
        _http = http;
        _url = url;
        if (budgetBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(budgetBytes));
        _budget = budgetBytes;
        Length = FetchBlock(0, learnLength: true);
    }

    public long Downloaded => Interlocked.Read(ref _downloaded);
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
        var (bytes, total) = Fetch(start, end, learnLength);
        _blocks[index] = bytes;
        return total;
    }

    /// <summary>
    /// Reads exactly <paramref name="count"/> bytes at <paramref name="offset"/> with one Range request, bypassing the
    /// block cache. For sampling small slices of a large file (e.g. tensor rows) without fetching whole blocks.
    /// </summary>
    public byte[] ReadRange(long offset, int count)
    {
        if (offset < 0 || count <= 0 || offset + count > Length)
            throw new ArgumentOutOfRangeException(nameof(offset), "The range is outside the file.");
        return Fetch(offset, offset + count - 1, learnLength: false).Bytes;
    }

    /// <summary>Fetches bytes [start, end]. Thread-safe, so <see cref="ReadRange"/> may be called in parallel.</summary>
    (byte[] Bytes, long Total) Fetch(long start, long end, bool learnLength)
    {
        var size = end - start + 1;
        lock (_budgetLock)
        {
            if (_reserved + size > _budget)
                throw new IOException($"Download budget of {_budget / (1 << 20)} MiB reached.");
            _reserved += size;
        }
        try
        {
            var resolved = _resolved;
            if (resolved is not null)
            {
                try
                {
                    return FetchFrom(resolved, start, end, learnLength);
                }
                catch (Exception ex) when (ex is IOException or HttpRequestException)
                {
                    _resolved = null; // the signed URL may have expired: go back through the original
                }
            }
            // Lineage checks make hundreds of small requests; one dropped connection should not fail the whole run.
            for (var attempt = 0; ; attempt++)
            {
                try
                {
                    return FetchFrom(_url, start, end, learnLength);
                }
                catch (Exception ex) when (attempt < 3 && ex is HttpRequestException or TaskCanceledException or IOException && ex is not AccessDeniedException)
                {
                    Thread.Sleep(1000 << attempt); // 1, 2, 4 s: TLS handshake failures tend to come in bursts
                }
            }
        }
        catch
        {
            lock (_budgetLock) _reserved -= size;
            throw;
        }
    }

    (byte[] Bytes, long Total) FetchFrom(Uri url, long start, long end, bool learnLength)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(start, end);
        using var response = _http.Send(request, HttpCompletionOption.ResponseHeadersRead);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new AccessDeniedException($"Access denied ({(int)response.StatusCode}). The repo may be gated: set HF_TOKEN.");
        if (response.StatusCode != HttpStatusCode.PartialContent)
            throw new IOException($"Server did not honour the range request (HTTP {(int)response.StatusCode}).");

        var range = response.Content.Headers.ContentRange;
        if (range?.Unit != "bytes" || range.Length is not > 0 || range.From != start ||
            range.To != Math.Min(end, range.Length.Value - 1) || (!learnLength && range.Length != Length))
            throw new IOException("Server returned an inconsistent Content-Range.");
        var count = checked((int)(range.To!.Value - start + 1));
        if (count <= 0 || count > end - start + 1 ||
            response.Content.Headers.ContentLength is { } contentLength && contentLength != count)
            throw new IOException("Range response exceeds its expected size.");
        using var body = response.Content.ReadAsStream();
        var bytes = new byte[count];
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        body.ReadExactlyAsync(bytes, timeout.Token).AsTask().GetAwaiter().GetResult();
        Interlocked.Add(ref _downloaded, bytes.Length);
        if (response.RequestMessage?.RequestUri is { Scheme: "https" } final && final != url && url == _url)
            _resolved = final;
        return (bytes, range.Length.Value);
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
