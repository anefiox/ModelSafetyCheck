using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ModelSafetyCheck.Hub;

public sealed record HfFile(string Path, long Size, string? Sha256);

public sealed record HfModelInfo(
    string Id,
    string Author,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? LastModified,
    long Downloads,
    bool Gated,
    IReadOnlyList<string> Tags,
    IReadOnlyList<string> BaseModels,
    string? DisplayedGgufTemplate,
    IReadOnlyList<HfFile> Files)
{
    public string? Revision { get; init; }
}

/// <summary>Minimal read-only Hugging Face Hub client. Sends HF_TOKEN only to huggingface.co, and only when set.</summary>
public sealed partial class HuggingFaceClient : IDisposable
{
    public const string Host = "https://huggingface.co";

    [GeneratedRegex(@"^[A-Za-z0-9][\w.\-]*/[\w.\-]+$")]
    private static partial Regex RepoIdRegex();

    readonly HttpClient _http;

    public HuggingFaceClient(HttpMessageHandler? handler = null)
    {
        _http = RemoteHttp.Create(handler);
    }

    public HttpClient Http => _http;

    /// <summary>Accepts "org/name" or a huggingface.co URL; returns null if it is neither.</summary>
    public static string? NormalizeRepoId(string input)
    {
        var id = input.Trim();
        foreach (var prefix in new[] { "https://huggingface.co/", "http://huggingface.co/", "huggingface.co/", "hf.co/", "hf:" })
            if (id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                id = id[prefix.Length..];
        var parts = id.Split('/');
        if (parts.Length > 2)
            id = $"{parts[0]}/{parts[1]}";
        return RepoIdRegex().IsMatch(id) && !id.Contains("..", StringComparison.Ordinal) ? id : null;
    }

    public Uri FileUrl(string repo, string path, string revision = "main") =>
        new($"{Host}/{repo}/resolve/{Uri.EscapeDataString(revision)}/{string.Join('/', path.Split('/').Select(Uri.EscapeDataString))}");

    public HfModelInfo GetModel(string repo)
    {
        using var response = _http.Send(new HttpRequestMessage(HttpMethod.Get, $"{Host}/api/models/{repo}?blobs=true"));
        if (response.StatusCode == HttpStatusCode.NotFound)
            throw new HttpRequestException($"Repository '{repo}' was not found (or is private: set HF_TOKEN).");
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new HttpRequestException($"Access to '{repo}' was denied. It may be gated or private: set HF_TOKEN.");
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(response.Content.ReadAsStream());
        var root = doc.RootElement;

        static string? Str(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        static DateTimeOffset? Date(JsonElement e, string name) => DateTimeOffset.TryParse(Str(e, name), out var d) ? d : null;

        var tags = root.TryGetProperty("tags", out var t) && t.ValueKind == JsonValueKind.Array
            ? t.EnumerateArray().Select(x => x.GetString() ?? "").ToList()
            : [];

        var baseModels = new List<string>();
        if (root.TryGetProperty("cardData", out var card) && card.ValueKind == JsonValueKind.Object && card.TryGetProperty("base_model", out var bm))
        {
            if (bm.ValueKind == JsonValueKind.String) baseModels.Add(bm.GetString()!);
            else if (bm.ValueKind == JsonValueKind.Array) baseModels.AddRange(bm.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0));
        }

        var files = new List<HfFile>();
        if (root.TryGetProperty("siblings", out var siblings))
            foreach (var s in siblings.EnumerateArray())
            {
                var lfs = s.TryGetProperty("lfs", out var l) && l.ValueKind == JsonValueKind.Object ? l : default;
                var size = s.TryGetProperty("size", out var sz) && sz.TryGetInt64(out var n) ? n : 0;
                files.Add(new HfFile(Str(s, "rfilename") ?? "", size, lfs.ValueKind == JsonValueKind.Object ? Str(lfs, "sha256") : null));
            }

        var gated = root.TryGetProperty("gated", out var g) && (g.ValueKind == JsonValueKind.String || g.ValueKind == JsonValueKind.True);
        var displayed = root.TryGetProperty("gguf", out var gguf) && gguf.ValueKind == JsonValueKind.Object ? Str(gguf, "chat_template") : null;

        return new HfModelInfo(Str(root, "id") ?? repo, Str(root, "author") ?? repo.Split('/')[0], Date(root, "createdAt"), Date(root, "lastModified"),
            root.TryGetProperty("downloads", out var dl) && dl.TryGetInt64(out var d) ? d : 0, gated, tags, baseModels, displayed, files)
            { Revision = Str(root, "sha") };
    }

    /// <summary>Downloads a small text file from the repo. Returns null when it does not exist.</summary>
    public string? GetText(string repo, string path, int maxBytes = 1 << 20, string revision = "main")
    {
        using var response = _http.Send(new HttpRequestMessage(HttpMethod.Get, FileUrl(repo, path, revision)), HttpCompletionOption.ResponseHeadersRead);
        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;
        response.EnsureSuccessStatusCode();
        using var body = response.Content.ReadAsStream();
        if (response.Content.Headers.ContentLength > maxBytes)
            throw new IOException($"{path} exceeds the {maxBytes}-byte text limit.");
        var buffer = new byte[checked(maxBytes + 1)];
        var read = 0;
        int n;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        while (read < buffer.Length && (n = body.ReadAsync(buffer.AsMemory(read), timeout.Token).AsTask().GetAwaiter().GetResult()) > 0)
            read += n;
        if (read > maxBytes)
            throw new IOException($"{path} exceeds the {maxBytes}-byte text limit.");
        return Encoding.UTF8.GetString(buffer, 0, read);
    }

    /// <summary>Enumerates paginated task search results. Missing tags cannot be discovered by a task search.</summary>
    public IEnumerable<string> ListModels(string task, int limit = int.MaxValue)
    {
        var count = 0;
        foreach (var model in SearchModels($"pipeline_tag={Uri.EscapeDataString(task)}&sort=downloads&direction=-1"))
        {
            if (count >= limit) yield break;
            if (model.GetProperty("id").GetString() is not { } id || NormalizeRepoId(id) != id) continue;
            count++;
            yield return id;
        }
    }

    /// <summary>
    /// Pages through /api/models with the given query string (without limit), yielding each model object. The caller stops
    /// enumerating when it has enough; at most <paramref name="maxPages"/> pages of 100 are fetched.
    /// </summary>
    public IEnumerable<JsonElement> SearchModels(string query, int maxPages = int.MaxValue)
    {
        string? url = $"{Host}/api/models?{query}&limit=100";
        for (var page = 0; url is not null && page < maxPages; page++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            using var response = _http.Send(request);
            response.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(response.Content.ReadAsStream());
            foreach (var model in doc.RootElement.EnumerateArray())
                yield return model.Clone();
            url = null;
            if (response.Headers.TryGetValues("Link", out var links))
                foreach (var link in links.SelectMany(l => l.Split(',')))
                {
                    var from = link.IndexOf('<');
                    var to = link.IndexOf('>');
                    if (!link.Contains("rel=\"next\"", StringComparison.Ordinal) || from < 0 || to <= from) continue;
                    if (!Uri.TryCreate(link[(from + 1)..to], UriKind.Absolute, out var next) ||
                        next.Scheme != "https" || next.Host != "huggingface.co" || !next.IsDefaultPort ||
                        !next.AbsolutePath.StartsWith("/api/models", StringComparison.Ordinal))
                        throw new IOException("Invalid Hugging Face pagination URL.");
                    url = next.AbsoluteUri;
                }
        }
    }

    public void Dispose() => _http.Dispose();
}
