using System.CommandLine;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Hub;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Cli;

/// <summary>`repo --discover`: find repos with a Hugging Face search instead of naming them, and skip ones already scanned.</summary>
sealed class DiscoverOptions
{
    public Option<bool> Enabled { get; } = new("--discover") { Description = "Find repos with a Hugging Face search instead of naming them. Repos scanned before are skipped unless their commit changed." };
    public Option<string[]> Search { get; } = new("--search") { Description = "Search term (repeatable; each term finds up to --limit repos), e.g. abliterated, uncensored, merge." };
    public Option<string[]> Filter { get; } = new("--filter") { Description = "Hub tag every repo must have (repeatable), e.g. gguf." };
    public Option<string?> Author { get; } = new("--author") { Description = "Only repos by this user or organisation." };
    public Option<string[]> Derived { get; } = new("--derived") { Description = "Only repos declaring this relation to a base model: finetune, merge, quantized, adapter, or any (repeatable)." };
    public Option<string> Sort { get; } = new("--sort") { Description = "created, modified, downloads or likes (newest or most first; see --ascending).", DefaultValueFactory = _ => "created" };
    public Option<bool> Ascending { get; } = new("--ascending") { Description = "Reverse the sort: oldest or least downloaded first." };
    public Option<long?> MaxDownloads { get; } = new("--max-downloads") { Description = "Only repos with at most this many downloads (obscure uploads)." };
    public Option<int> Limit { get; } = new("--limit") { Description = "Repos to discover per search term (scanned or skipped).", DefaultValueFactory = _ => 50 };
    public Option<string> State { get; } = new("--state") { Description = "File recording which commit of each repo was scanned.", DefaultValueFactory = _ => DiscoverState.DefaultPath };
    public Option<bool> Rescan { get; } = new("--rescan") { Description = "Scan discovered repos even if their commit was scanned before." };

    public static DiscoverOptions AddTo(Command command)
    {
        var options = new DiscoverOptions();
        options.Sort.AcceptOnlyFromAmong("created", "modified", "downloads", "likes");
        foreach (var option in new Option[] { options.Enabled, options.Search, options.Filter, options.Author, options.Derived, options.Sort,
                     options.Ascending, options.MaxDownloads, options.Limit, options.State, options.Rescan })
            command.Options.Add(option);
        return options;
    }

    public bool TryCreate(ParseResult result, out DiscoverQuery query, out DiscoverState state, out string error)
    {
        query = null!;
        state = null!;
        var derived = result.GetValue(Derived) ?? [];
        if (derived.FirstOrDefault(d => !HfDiscovery.KnownRelations.Contains(d)) is { } bad)
        {
            error = $"--derived must be one of {string.Join(", ", HfDiscovery.KnownRelations)}, not '{bad}'.";
            return false;
        }
        if (result.GetValue(Limit) <= 0)
        {
            error = "--limit must be positive.";
            return false;
        }
        query = new DiscoverQuery
        {
            Search = result.GetValue(Search) ?? [],
            Filters = result.GetValue(Filter) ?? [],
            Author = result.GetValue(Author),
            Relations = derived,
            Sort = Enum.Parse<DiscoverSort>(result.GetValue(Sort)!, ignoreCase: true),
            Ascending = result.GetValue(Ascending),
            MaxDownloads = result.GetValue(MaxDownloads),
            Limit = result.GetValue(Limit),
        };
        try
        {
            state = DiscoverState.Load(result.GetValue(State)!);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            error = $"Could not read the discovery state: {ex.Message}";
            return false;
        }
        error = "";
        return true;
    }

    public static IEnumerable<ScanReport> Scans(DiscoverQuery query, DiscoverState state, bool rescan, RepoScanOptions options)
    {
        using var client = new HuggingFaceClient();
        int found = 0, skipped = 0;
        IEnumerator<HfListedModel> models;
        string? discoveryError = null;
        try
        {
            models = HfDiscovery.Discover(client, query).GetEnumerator();
        }
        catch (Exception ex) when (ex is IOException or HttpRequestException)
        {
            models = Enumerable.Empty<HfListedModel>().GetEnumerator();
            discoveryError = ex.Message;
        }
        using (models)
        {
            while (true)
            {
                HfListedModel model;
                try
                {
                    if (!models.MoveNext()) break;
                    model = models.Current;
                }
                catch (Exception ex) when (ex is IOException or HttpRequestException or TaskCanceledException)
                {
                    discoveryError = ex.Message;
                    break;
                }
                found++;
                if (!rescan && state.IsUnchanged(model))
                {
                    skipped++;
                    continue;
                }
                Console.Error.WriteLine($"[{found}] {model.Id} ({model.Downloads} downloads, created {model.CreatedAt:yyyy-MM-dd})");
                var reports = RepoScanner.Scan(client, model.Id, options).ToList();
                foreach (var report in reports)
                    yield return report;
                // Repos that failed to scan stay unrecorded, so the next run tries them again.
                if (reports.All(r => r.Error is null))
                    state.Record(model, reports.SelectMany(r => r.Findings).Where(f => f.Counts).Select(f => (Severity?)f.Severity).Max()?.ToString());
            }
        }
        Console.Error.WriteLine($"Discovered {found} repo(s); skipped {skipped} unchanged since an earlier scan.");
        if (discoveryError is not null)
            yield return new ScanReport { Target = "hf:discover", Kind = "hf", Error = $"Hugging Face search failed: {discoveryError}" };
    }
}
