// Rebuilds data/known-templates.json from the official repos listed in data/template-sources.json.
// Usage: dotnet run --project tools/TemplateDbBuilder -- [--history] [--gguf-history N] [--only org/repo] [repo-root]
//   --history         also record earlier versions of each template (D-07), so a stale-but-official
//                     download matches exactly. Template files are read at recent commits; for GGUF repos the
//                     header of up to N earlier uploads (default 3) is read with HTTP Range requests (~16 MiB each).
//   --only org/repo   rebuild just that source and merge it into the existing database.
// Set HF_TOKEN to read gated repos. The output version is the build date (yyyyMMdd), so a newer
// database always overrides an older embedded one.

using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Data;
using ModelSafetyCheck.Hub;
using ModelSafetyCheck.Rules;

var history = args.Contains("--history");
var ggufHistory = args.SkipWhile(a => a != "--gguf-history").Skip(1).FirstOrDefault() is { } g && int.TryParse(g, out var gh) ? gh : 3;
var only = args.SkipWhile(a => a != "--only").Skip(1).FirstOrDefault();
var root = args.LastOrDefault(a => !a.StartsWith("--", StringComparison.Ordinal) && a != only && !int.TryParse(a, out _)) ?? FindRepoRoot();
var sourcesPath = Path.Combine(root, "data", "template-sources.json");
var outputPath = Path.Combine(root, "data", "known-templates.json");

using var client = new HuggingFaceClient();
var http = client.Http;

using var sourcesDoc = JsonDocument.Parse(File.ReadAllText(sourcesPath));
var sources = sourcesDoc.RootElement.GetProperty("sources").EnumerateArray()
    .Where(s => only is null || s.GetProperty("repo").GetString() == only)
    .ToList();
var templates = new List<KnownTemplate>();
var failures = new List<string>();

foreach (var source in sources)
{
    var family = source.GetProperty("family").GetString()!;
    var repo = source.GetProperty("repo").GetString()!;
    var kind = source.GetProperty("kind").GetString()!;
    var via = source.TryGetProperty("via", out var v) ? v.GetString() : null;
    KnownTemplate Make(string? name, string text, string? revision = null, string? date = null) =>
        new(family, $"https://huggingface.co/{repo}", kind, name, via, ModelScanner.Sha256(text), KnownTemplateCheck.NormalizedHash(text), text, revision, date);

    try
    {
        var found = kind == "gguf" ? await FromGguf(repo) : await FromTokenizerConfig(repo, "main");
        if (found.Count == 0)
        {
            failures.Add($"{repo}: no chat template found");
            continue;
        }
        templates.AddRange(found.Select(f => Make(f.Name, f.Text)));

        var older = 0;
        if (history)
        {
            var known = found.Select(f => KnownTemplateCheck.NormalizedHash(f.Text)).ToHashSet();
            var previous = kind == "gguf" ? GgufHistory(repo, ggufHistory) : TokenizerHistory(repo);
            await foreach (var (name, text, revision, date) in previous)
                if (known.Add(KnownTemplateCheck.NormalizedHash(text)))
                {
                    templates.Add(Make(name, text, revision, date));
                    older++;
                }
        }
        Console.WriteLine($"ok    {repo} ({found.Count}{(history ? $" + {older} earlier" : "")})");
    }
    catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException or KeyNotFoundException or InvalidOperationException or IOException)
    {
        failures.Add($"{repo}: {ex.Message}");
        Console.WriteLine($"fail  {repo}: {ex.Message}");
    }
}

// --only merges into the existing database instead of replacing it.
if (only is not null && File.Exists(outputPath))
{
    var existing = JsonSerializer.Deserialize(File.ReadAllText(outputPath), DataJsonContext.Default.KnownTemplateFile)!;
    templates = existing.Templates.Where(t => t.Source != $"https://huggingface.co/{only}").Concat(templates).ToList();
}

var unique = templates.DistinctBy(t => (t.NormalizedSha256, t.Source, t.Name)).ToList();
var version = int.Parse(DateTime.UtcNow.ToString("yyyyMMdd"));
var file = new KnownTemplateFile(version, DateTime.UtcNow.ToString("yyyy-MM-dd"), unique);
File.WriteAllText(outputPath, JsonSerializer.Serialize(file, DataJsonContext.Default.KnownTemplateFile) + "\n");
Console.WriteLine($"\nWrote {unique.Count} templates ({unique.DistinctBy(t => t.NormalizedSha256).Count()} distinct, {unique.Count(t => t.Revision is not null)} earlier versions) to {outputPath}");
if (failures.Count > 0)
    Console.WriteLine($"{failures.Count} source(s) failed:\n  " + string.Join("\n  ", failures));
return failures.Count == sources.Count && sources.Count > 0 ? 1 : 0;

async Task<List<(string? Name, string Text)>> FromGguf(string repo)
{
    using var doc = JsonDocument.Parse(await http.GetStringAsync($"https://huggingface.co/api/models/{repo}"));
    return doc.RootElement.TryGetProperty("gguf", out var gguf) && gguf.TryGetProperty("chat_template", out var t) && t.GetString() is { Length: > 0 } text
        ? [(null, text)]
        : [];
}

async Task<List<(string? Name, string Text)>> FromTokenizerConfig(string repo, string revision)
{
    // Newer repos ship the template as its own file.
    using (var jinja = await http.GetAsync($"https://huggingface.co/{repo}/resolve/{revision}/chat_template.jinja"))
        if (jinja.StatusCode == HttpStatusCode.OK)
            return [(null, await jinja.Content.ReadAsStringAsync())];

    using var response = await http.GetAsync($"https://huggingface.co/{repo}/resolve/{revision}/tokenizer_config.json");
    if (response.StatusCode == HttpStatusCode.NotFound && revision != "main")
        return [];
    response.EnsureSuccessStatusCode();
    using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    if (!doc.RootElement.TryGetProperty("chat_template", out var template))
        return [];
    return template.ValueKind switch
    {
        JsonValueKind.String => [(null, template.GetString()!)],
        JsonValueKind.Array => template.EnumerateArray()
            .Select(t => ((string?)t.GetProperty("name").GetString(), t.GetProperty("template").GetString()!))
            .ToList(),
        _ => [],
    };
}

async Task<List<(string Id, string Date, string Title)>> Commits(string repo)
{
    using var doc = JsonDocument.Parse(await http.GetStringAsync($"https://huggingface.co/api/models/{repo}/commits/main"));
    return doc.RootElement.EnumerateArray()
        .Select(c => (c.GetProperty("id").GetString()!, (c.GetProperty("date").GetString() ?? "")[..Math.Min(10, (c.GetProperty("date").GetString() ?? "").Length)], c.GetProperty("title").GetString() ?? ""))
        .ToList();
}

/// <summary>Template files at the most recent commits (skipping the current one). Small files, so cheap.</summary>
async IAsyncEnumerable<(string? Name, string Text, string Revision, string Date)> TokenizerHistory(string repo)
{
    foreach (var (id, date, _) in (await Commits(repo)).Skip(1).Take(12))
        foreach (var (name, text) in await FromTokenizerConfig(repo, id))
            yield return (name, text, id, date);
}

/// <summary>
/// The embedded template of earlier GGUF uploads. Commit titles name the uploaded file; the smallest earlier
/// uploads are read header-only at that revision.
/// </summary>
async IAsyncEnumerable<(string? Name, string Text, string Revision, string Date)> GgufHistory(string repo, int max)
{
    var info = client.GetModel(repo);
    var sizes = info.Files.ToDictionary(f => f.Path, f => f.Size);
    var uploads = (await Commits(repo)).Skip(1)
        .Select(c => (c.Id, c.Date, File: Regex.Match(c.Title, @"[\w.\-]+\.gguf").Value))
        .Where(c => c.File.Length > 0 && !c.File.StartsWith("mmproj", StringComparison.OrdinalIgnoreCase) && !Regex.IsMatch(c.File, @"-0000[2-9]-of-"))
        .OrderBy(c => sizes.GetValueOrDefault(c.File, long.MaxValue))
        .Take(max)
        .ToList();
    foreach (var (id, date, path) in uploads)
    {
        string? template = null;
        try
        {
            using var stream = new HttpRangeStream(http, new Uri($"https://huggingface.co/{repo}/resolve/{id}/{Uri.EscapeDataString(path)}"), 64L << 20);
            template = GgufParser.Parse(stream).GetString("tokenizer.chat_template");
        }
        catch (IOException ex)
        {
            Console.WriteLine($"      {repo}@{id[..10]}/{path}: {ex.Message}");
        }
        if (template is { Length: > 0 })
            yield return (null, template, id, date);
    }
}

static string FindRepoRoot()
{
    for (var dir = new DirectoryInfo(Environment.CurrentDirectory); dir is not null; dir = dir.Parent)
        if (File.Exists(Path.Combine(dir.FullName, "ModelSafetyCheck.slnx")))
            return dir.FullName;
    throw new InvalidOperationException("Run from inside the repository or pass its path.");
}
