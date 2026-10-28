using System.Text.Json;
using ModelSafetyCheck.Jinja;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Local;

public static partial class LocalModels
{
    /// <summary>Every local source: Ollama, LM Studio (models and per-model overrides), llama.cpp and Hugging Face caches.</summary>
    public static IEnumerable<ScanReport> ScanAll()
    {
        var seen = new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (var report in ScanOllama())
            yield return report;
        foreach (var report in ScanLmStudio())
        {
            seen.Add(report.Path ?? report.Target);
            yield return report;
        }
        foreach (var report in ScanLmStudioOverrides())
            yield return report;
        foreach (var (root, label) in CacheRoots())
            foreach (var report in ScanCache(root, label, seen))
                yield return report;
    }

    static IEnumerable<(string Root, string Label)> CacheRoots()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var llama = Environment.GetEnvironmentVariable("LLAMA_CACHE") is { Length: > 0 } lc ? lc
            : OperatingSystem.IsWindows() ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "llama.cpp")
            : OperatingSystem.IsMacOS() ? Path.Combine(home, "Library", "Caches", "llama.cpp")
            : Path.Combine(Environment.GetEnvironmentVariable("XDG_CACHE_HOME") is { Length: > 0 } xdg ? xdg : Path.Combine(home, ".cache"), "llama.cpp");
        yield return (llama, "llama.cpp-cache");

        var hub = Environment.GetEnvironmentVariable("HF_HUB_CACHE") is { Length: > 0 } hc ? hc
            : Environment.GetEnvironmentVariable("HF_HOME") is { Length: > 0 } hh ? Path.Combine(hh, "hub")
            : Path.Combine(home, ".cache", "huggingface", "hub");
        yield return (hub, "hf-cache");
    }

    /// <summary>llama.cpp (-hf downloads) and the Hugging Face hub cache. Hub snapshots are symlinks into blobs, so targets are de-duplicated.</summary>
    public static IEnumerable<ScanReport> ScanCache(string root, string label, HashSet<string>? seen = null)
    {
        if (!Directory.Exists(root))
            yield break;
        seen ??= [];
        foreach (var path in Directory.EnumerateFiles(root, "*.gguf", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }))
        {
            string resolved;
            try
            {
                resolved = new FileInfo(path).ResolveLinkTarget(returnFinalTarget: true)?.FullName ?? path;
            }
            catch (IOException)
            {
                resolved = path;
            }
            if (!seen.Add(resolved))
                continue;
            yield return ModelScanner.ScanFile(resolved, label, $"{label}:{Path.GetRelativePath(root, path).Replace('\\', '/')}");
        }
    }

    /// <summary>
    /// LM Studio lets users replace a model's prompt template and system prompt in per-model defaults and presets.
    /// Like Ollama's template layer, an override is what actually runs, so it is scanned too.
    /// </summary>
    public static IEnumerable<ScanReport> ScanLmStudioOverrides(string? lmStudioHome = null)
    {
        lmStudioHome ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".lmstudio");
        var dirs = new[] { Path.Combine(lmStudioHome, ".internal", "user-concrete-model-default-config"), Path.Combine(lmStudioHome, "config-presets") };
        foreach (var dir in dirs.Where(Directory.Exists))
        {
            foreach (var file in Directory.EnumerateFiles(dir, "*.json", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }))
            {
                var report = new ScanReport { Target = $"lmstudio-config:{Path.GetRelativePath(lmStudioHome, file).Replace('\\', '/')}", Kind = "lmstudio-config", Path = file };
                try
                {
                    if (new FileInfo(file).Length > MaxTextLayerBytes)
                        continue;
                    using var doc = JsonDocument.Parse(File.ReadAllText(file));
                    WalkLmStudioConfig(doc.RootElement, "", report);
                }
                catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
                {
                    report.Error = ex.Message;
                }
                if (report.ContentHashes.Count > 0 || report.Error is not null)
                    yield return report;
            }
        }
    }

    /// <summary>
    /// LM Studio stores settings as nested objects and as {"key": "...", "value": ...} pairs, so the context
    /// for a string is every property name and "key" value on the way down.
    /// </summary>
    static void WalkLmStudioConfig(JsonElement element, string context, ScanReport report)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var key = element.TryGetProperty("key", out var k) && k.ValueKind == JsonValueKind.String ? k.GetString() : null;
                foreach (var property in element.EnumerateObject().Where(p => !(p.Name == "key" && key is not null)))
                    WalkLmStudioConfig(property.Value, $"{context}/{key}/{property.Name}", report);
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                    WalkLmStudioConfig(item, context, report);
                break;
            case JsonValueKind.String:
                var text = element.GetString() ?? "";
                if (text.Length == 0)
                    break;
                var location = context.Replace("//", "/").Trim('/');
                if (context.Contains("systemPrompt", StringComparison.OrdinalIgnoreCase))
                    ModelScanner.ScanSystemPrompt(report, text, location);
                else if ((context.Contains("promptTemplate", StringComparison.OrdinalIgnoreCase) || context.Contains("jinja", StringComparison.OrdinalIgnoreCase)) &&
                         (text.Contains("{%", StringComparison.Ordinal) || text.Contains("{{", StringComparison.Ordinal)))
                    ModelScanner.ScanTemplate(report, text, TemplateDialect.Jinja, location);
                break;
        }
    }
}
