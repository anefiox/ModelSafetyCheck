using System.Text.Json;
using System.Text.Json.Serialization;

namespace ModelSafetyCheck.Hub;

/// <summary>A repo from a Hugging Face model search.</summary>
public sealed record HfListedModel(string Id, string? Sha, DateTimeOffset? CreatedAt, DateTimeOffset? LastModified, long Downloads, IReadOnlyList<string> Tags)
{
    /// <summary>How the repo says it relates to its base model: finetune, merge, quantized or adapter (from base_model:&lt;relation&gt;:... tags).</summary>
    public IEnumerable<string> Relations => Tags
        .Select(t => t.Split(':'))
        .Where(p => p.Length >= 3 && p[0] == "base_model")
        .Select(p => p[1])
        .Distinct();

    /// <summary>Has any base_model tag: a derivative of some other model.</summary>
    public bool IsDerived => Tags.Any(t => t.StartsWith("base_model:", StringComparison.Ordinal));
}

public enum DiscoverSort { Created, Modified, Downloads, Likes }

/// <summary>What `repo --discover` looks for. Search terms are run one after another, each up to <see cref="Limit"/> repos.</summary>
public sealed record DiscoverQuery
{
    public IReadOnlyList<string> Search { get; init; } = [];

    /// <summary>Hub tags every repo must have (sent to the Hub), e.g. gguf.</summary>
    public IReadOnlyList<string> Filters { get; init; } = [];

    public string? Author { get; init; }
    public DiscoverSort Sort { get; init; } = DiscoverSort.Created;
    public bool Ascending { get; init; }

    /// <summary>Keep only repos with one of these base-model relations (finetune, merge, quantized, adapter), or "any" for every derivative.</summary>
    public IReadOnlyList<string> Relations { get; init; } = [];

    public long? MaxDownloads { get; init; }
    public int Limit { get; init; } = 50;

    /// <summary>Pages of 100 read per search term before giving up on client-side filters.</summary>
    public int MaxPages { get; init; } = 50;
}

public static class HfDiscovery
{
    public static readonly string[] KnownRelations = ["finetune", "merge", "quantized", "adapter", "any"];

    public static string QueryString(DiscoverQuery query, string? search)
    {
        var parts = new List<string>
        {
            "sort=" + query.Sort switch
            {
                DiscoverSort.Modified => "lastModified",
                DiscoverSort.Downloads => "downloads",
                DiscoverSort.Likes => "likes",
                _ => "createdAt",
            },
            "direction=" + (query.Ascending ? "1" : "-1"),
        };
        if (search is not null) parts.Add("search=" + Uri.EscapeDataString(search));
        if (query.Author is not null) parts.Add("author=" + Uri.EscapeDataString(query.Author));
        parts.AddRange(query.Filters.Select(f => "filter=" + Uri.EscapeDataString(f)));
        parts.AddRange(new[] { "sha", "createdAt", "lastModified", "downloads", "tags" }.Select(e => "expand%5B%5D=" + e));
        return string.Join('&', parts);
    }

    public static HfListedModel Parse(JsonElement model)
    {
        static DateTimeOffset? Date(JsonElement m, string name) =>
            m.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(v.GetString(), out var d) ? d : null;
        var tags = model.TryGetProperty("tags", out var t) && t.ValueKind == JsonValueKind.Array
            ? t.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList()
            : [];
        return new HfListedModel(
            model.GetProperty("id").GetString() ?? "",
            model.TryGetProperty("sha", out var sha) && sha.ValueKind == JsonValueKind.String ? sha.GetString() : null,
            Date(model, "createdAt"),
            Date(model, "lastModified"),
            model.TryGetProperty("downloads", out var dl) && dl.TryGetInt64(out var n) ? n : 0,
            tags);
    }

    public static bool Matches(HfListedModel model, DiscoverQuery query) =>
        (query.MaxDownloads is not { } max || model.Downloads <= max) &&
        (query.Relations.Count == 0 ||
         query.Relations.Contains("any") && model.IsDerived ||
         model.Relations.Any(query.Relations.Contains));

    /// <summary>Repos matching the query, deduplicated across search terms.</summary>
    public static IEnumerable<HfListedModel> Discover(HuggingFaceClient client, DiscoverQuery query)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var search in query.Search.Count == 0 ? [null] : query.Search.Select(s => (string?)s))
        {
            var count = 0;
            foreach (var element in client.SearchModels(QueryString(query, search), query.MaxPages))
            {
                if (count >= query.Limit) break;
                var model = Parse(element);
                if (HuggingFaceClient.NormalizeRepoId(model.Id) != model.Id || !Matches(model, query) || !seen.Add(model.Id))
                    continue;
                count++;
                yield return model;
            }
        }
    }
}

public sealed record DiscoverStateEntry(string? Sha, DateTimeOffset Scanned, string? MaxSeverity);

public sealed record DiscoverStateFile(int Version, Dictionary<string, DiscoverStateEntry> Repos);

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(DiscoverStateFile))]
internal sealed partial class DiscoverJsonContext : JsonSerializerContext;

/// <summary>
/// Remembers which commit of each discovered repo was scanned, so repeated `repo --discover` runs only scan repos that are
/// new or have changed since.
/// </summary>
public sealed class DiscoverState
{
    readonly string _path;
    readonly DiscoverStateFile _file;

    DiscoverState(string path, DiscoverStateFile file)
    {
        _path = path;
        _file = file;
    }

    public static string DefaultPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".modelcheck", "discover-state.json");

    public int Count => _file.Repos.Count;

    public static DiscoverState Load(string path)
    {
        if (!File.Exists(path))
            return new DiscoverState(path, new DiscoverStateFile(1, new(StringComparer.OrdinalIgnoreCase)));
        var file = JsonSerializer.Deserialize(File.ReadAllText(path), DiscoverJsonContext.Default.DiscoverStateFile)
            ?? throw new IOException($"{path} is empty.");
        return new DiscoverState(path, file with { Repos = new(file.Repos, StringComparer.OrdinalIgnoreCase) });
    }

    /// <summary>True when the repo was never scanned, or its commit changed. A repo without a known sha is always scanned.</summary>
    public bool IsUnchanged(HfListedModel model) =>
        model.Sha is not null && _file.Repos.TryGetValue(model.Id, out var entry) && entry.Sha == model.Sha;

    public void Record(HfListedModel model, string? maxSeverity)
    {
        _file.Repos[model.Id] = new DiscoverStateEntry(model.Sha, DateTimeOffset.UtcNow, maxSeverity);
        Save();
    }

    void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
        // Write then rename, so a run killed mid-write cannot leave a truncated state file.
        var temp = _path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(_file, DiscoverJsonContext.Default.DiscoverStateFile));
        File.Move(temp, _path, overwrite: true);
    }
}
