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
    IReadOnlyList<HfFile> Files);

/// <summary>Minimal read-only Hugging Face Hub client. Sends HF_TOKEN only to huggingface.co, and only when set.</summary>
public sealed partial class HuggingFaceClient : IDisposable
{
    public const string Host = "https://huggingface.co";

    [GeneratedRegex(@"^[A-Za-z0-9][\w.\-]*/[\w.\-]+$")]
    private static partial Regex RepoIdRegex();

    readonly HttpClient _http;

    public HuggingFaceClient(HttpMessageHandler? handler = null)
    {
        // .NET drops the Authorization header when a redirect leaves the original host (e.g. to the CDN).
        _http = handler is null ? new HttpClient() : new HttpClient(handler);
        _http.Timeout = TimeSpan.FromSeconds(60);
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"modelcheck/{typeof(HuggingFaceClient).Assembly.GetName().Version?.ToString(3) ?? "0"}");
        if (Environment.GetEnvironmentVariable("HF_TOKEN") is { Length: > 0 } token)
            _http.DefaultRequestHeaders.Authorization = new("Bearer", token);
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

    public Uri FileUrl(string repo, string path) =>
        new($"{Host}/{repo}/resolve/main/{string.Join('/', path.Split('/').Select(Uri.EscapeDataString))}");

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
            root.TryGetProperty("downloads", out var dl) && dl.TryGetInt64(out var d) ? d : 0, gated, tags, baseModels, displayed, files);
    }

    /// <summary>Downloads a small text file from the repo. Returns null when it does not exist.</summary>
    public string? GetText(string repo, string path, int maxBytes = 1 << 20)
    {
        using var response = _http.Send(new HttpRequestMessage(HttpMethod.Get, FileUrl(repo, path)), HttpCompletionOption.ResponseHeadersRead);
        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;
        response.EnsureSuccessStatusCode();
        using var body = response.Content.ReadAsStream();
        var buffer = new byte[maxBytes];
        var read = 0;
        int n;
        while (read < maxBytes && (n = body.Read(buffer, read, maxBytes - read)) > 0)
            read += n;
        return Encoding.UTF8.GetString(buffer, 0, read);
    }

    public void Dispose() => _http.Dispose();
}
