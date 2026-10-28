// Rebuilds data/known-templates.json from the official repos listed in data/template-sources.json.
// Usage: dotnet run --project tools/TemplateDbBuilder -- [repo-root]
// Set HF_TOKEN to read gated repos. The output version is the build date (yyyyMMdd), so a newer
// database always overrides an older embedded one.

using System.Net;
using System.Text.Json;
using ModelSafetyCheck.Data;
using ModelSafetyCheck.Rules;

var root = args.Length > 0 ? args[0] : FindRepoRoot();
var sourcesPath = Path.Combine(root, "data", "template-sources.json");
var outputPath = Path.Combine(root, "data", "known-templates.json");

using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
http.DefaultRequestHeaders.UserAgent.ParseAdd("modelcheck-template-db/1.0");
if (Environment.GetEnvironmentVariable("HF_TOKEN") is { Length: > 0 } token)
    http.DefaultRequestHeaders.Authorization = new("Bearer", token);

using var sourcesDoc = JsonDocument.Parse(File.ReadAllText(sourcesPath));
var templates = new List<KnownTemplate>();
var failures = new List<string>();

foreach (var source in sourcesDoc.RootElement.GetProperty("sources").EnumerateArray())
{
    var family = source.GetProperty("family").GetString()!;
    var repo = source.GetProperty("repo").GetString()!;
    var kind = source.GetProperty("kind").GetString()!;
    var via = source.TryGetProperty("via", out var v) ? v.GetString() : null;

    try
    {
        var found = kind == "gguf" ? await FromGguf(repo) : await FromTokenizerConfig(repo);
        if (found.Count == 0)
        {
            failures.Add($"{repo}: no chat template found");
            continue;
        }
        foreach (var (name, text) in found)
            templates.Add(new KnownTemplate(family, $"https://huggingface.co/{repo}", kind, name, via,
                ModelScanner.Sha256(text), KnownTemplateCheck.NormalizedHash(text), text));
        Console.WriteLine($"ok    {repo} ({found.Count})");
    }
    catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException or KeyNotFoundException or InvalidOperationException)
    {
        failures.Add($"{repo}: {ex.Message}");
        Console.WriteLine($"fail  {repo}: {ex.Message}");
    }
}

var unique = templates.DistinctBy(t => (t.NormalizedSha256, t.Source, t.Name)).ToList();
var version = int.Parse(DateTime.UtcNow.ToString("yyyyMMdd"));
var file = new KnownTemplateFile(version, DateTime.UtcNow.ToString("yyyy-MM-dd"), unique);
File.WriteAllText(outputPath, JsonSerializer.Serialize(file, DataJsonContext.Default.KnownTemplateFile) + "\n");
Console.WriteLine($"\nWrote {unique.Count} templates ({unique.DistinctBy(t => t.NormalizedSha256).Count()} distinct) to {outputPath}");
if (failures.Count > 0)
    Console.WriteLine($"{failures.Count} source(s) failed:\n  " + string.Join("\n  ", failures));
return failures.Count == sourcesDoc.RootElement.GetProperty("sources").GetArrayLength() ? 1 : 0;

async Task<List<(string? Name, string Text)>> FromGguf(string repo)
{
    using var doc = JsonDocument.Parse(await http.GetStringAsync($"https://huggingface.co/api/models/{repo}"));
    return doc.RootElement.TryGetProperty("gguf", out var gguf) && gguf.TryGetProperty("chat_template", out var t) && t.GetString() is { Length: > 0 } text
        ? [(null, text)]
        : [];
}

async Task<List<(string? Name, string Text)>> FromTokenizerConfig(string repo)
{
    // Newer repos ship the template as its own file.
    using (var jinja = await http.GetAsync($"https://huggingface.co/{repo}/resolve/main/chat_template.jinja"))
        if (jinja.StatusCode == HttpStatusCode.OK)
            return [(null, await jinja.Content.ReadAsStringAsync())];

    using var response = await http.GetAsync($"https://huggingface.co/{repo}/resolve/main/tokenizer_config.json");
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

static string FindRepoRoot()
{
    for (var dir = new DirectoryInfo(Environment.CurrentDirectory); dir is not null; dir = dir.Parent)
        if (File.Exists(Path.Combine(dir.FullName, "ModelSafetyCheck.slnx")))
            return dir.FullName;
    throw new InvalidOperationException("Run from inside the repository or pass its path.");
}
