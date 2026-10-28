using System.Text.Json;
using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Jinja;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Local;

/// <summary>Finds models installed by local runners and scans what each runner will actually use.</summary>
public static partial class LocalModels
{
    const string ModelMediaType = "application/vnd.ollama.image.model";
    const string ProjectorMediaType = "application/vnd.ollama.image.projector";
    const string AdapterMediaType = "application/vnd.ollama.image.adapter";
    const string TemplateMediaType = "application/vnd.ollama.image.template";
    const string SystemMediaType = "application/vnd.ollama.image.system";
    const long MaxTextLayerBytes = 1 << 20;

    [GeneratedRegex("^sha256:[0-9a-f]{64}$")]
    private static partial Regex DigestRegex();

    static string Home => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    public static IEnumerable<string> LmStudioRoots()
    {
        var roots = new List<string> { Path.Combine(Home, ".lmstudio", "models"), Path.Combine(Home, ".cache", "lm-studio", "models") };
        var settings = Path.Combine(Home, ".lmstudio", "settings.json");
        try
        {
            if (File.Exists(settings))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(settings));
                if (doc.RootElement.TryGetProperty("downloadsFolder", out var folder) && folder.ValueKind == JsonValueKind.String)
                    roots.Insert(0, folder.GetString()!);
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // A broken settings file just means we fall back to the default locations.
        }
        return roots.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);
    }

    public static IEnumerable<string> OllamaModelDirs()
    {
        var env = Environment.GetEnvironmentVariable("OLLAMA_MODELS");
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(env))
            candidates.Add(env);
        candidates.Add(Path.Combine(Home, ".ollama", "models"));
        if (!OperatingSystem.IsWindows())
        {
            candidates.Add("/usr/share/ollama/.ollama/models");
            candidates.Add("/var/lib/ollama/.ollama/models");
        }
        return candidates.Where(d => Directory.Exists(Path.Combine(d, "manifests"))).Distinct();
    }

    public static IEnumerable<ScanReport> ScanLmStudio(IEnumerable<string>? roots = null)
    {
        foreach (var root in roots ?? LmStudioRoots())
            foreach (var path in Directory.EnumerateFiles(root, "*.gguf", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }))
                yield return ModelScanner.ScanFile(path, "lmstudio", $"lmstudio:{Path.GetRelativePath(root, path).Replace('\\', '/')}");
    }

    /// <summary>
    /// Scans every Ollama manifest. Ollama stores the chat template as its own layer, which overrides the
    /// GGUF's embedded template, so that layer is scanned too: it is the template that actually runs.
    /// </summary>
    public static IEnumerable<ScanReport> ScanOllama(IEnumerable<string>? modelDirs = null)
    {
        foreach (var dir in modelDirs ?? OllamaModelDirs())
        {
            var manifests = Path.Combine(dir, "manifests");
            foreach (var manifest in Directory.EnumerateFiles(manifests, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }))
                yield return ScanOllamaManifest(dir, manifest);
        }
    }

    static ScanReport ScanOllamaManifest(string modelsDir, string manifestPath)
    {
        var report = new ScanReport { Target = $"ollama:{OllamaName(Path.Combine(modelsDir, "manifests"), manifestPath)}", Kind = "ollama" };
        List<(string MediaType, string Digest)> layers;
        string? configDigest = null;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(manifestPath));
            layers = doc.RootElement.GetProperty("layers").EnumerateArray()
                .Select(l => (l.GetProperty("mediaType").GetString() ?? "", l.GetProperty("digest").GetString() ?? ""))
                .ToList();
            if (doc.RootElement.TryGetProperty("config", out var config) && config.TryGetProperty("digest", out var cd))
                configDigest = cd.GetString();
        }
        catch (Exception ex) when (ex is IOException or JsonException or KeyNotFoundException or InvalidOperationException or UnauthorizedAccessException)
        {
            report.Error = $"Could not read manifest {manifestPath}: {ex.Message}";
            return report;
        }

        var hasModelTemplate = false;
        foreach (var (mediaType, digest) in layers)
        {
            if (!DigestRegex().IsMatch(digest))
            {
                report.Findings.Add(new Finding("O001", Severity.High, "Malformed layer digest in Ollama manifest",
                    $"Layer digest '{digest}' is not a sha256 digest. Crafted digests were used for path traversal (Ollama, 2024); this layer was not opened.",
                    manifestPath));
                continue;
            }
            var blob = Path.Combine(modelsDir, "blobs", digest.Replace(':', '-'));
            if (!File.Exists(blob))
            {
                report.Findings.Add(new Finding("O002", Severity.Low, "Missing Ollama blob", $"{mediaType} layer {digest} is referenced but not on disk.", manifestPath));
                continue;
            }

            switch (mediaType)
            {
                case ModelMediaType or ProjectorMediaType or AdapterMediaType:
                    var label = mediaType[(mediaType.LastIndexOf('.') + 1)..];
                    try
                    {
                        using var stream = new FileStream(blob, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20);
                        var before = report.Templates.Count;
                        ModelScanner.ScanGguf(stream, report, $"{label}/");
                        if (mediaType == ModelMediaType)
                        {
                            hasModelTemplate = report.Templates.Count > before;
                            report.Fingerprint = digest;
                        }
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        report.Error = ex.Message;
                    }
                    break;
                case TemplateMediaType:
                    if (ReadTextLayer(blob, report, "template") is { } template)
                        ModelScanner.ScanTemplate(report, template, TemplateDialect.GoTemplate, "ollama template layer");
                    break;
                case SystemMediaType:
                    if (ReadTextLayer(blob, report, "system") is { } system)
                        ModelScanner.ScanSystemPrompt(report, system, "ollama system layer");
                    break;
            }
        }

        CheckOllamaConfig(modelsDir, configDigest, report);

        if (hasModelTemplate && layers.Any(l => l.MediaType == TemplateMediaType))
            report.Findings.Add(new Finding("O003", Severity.Info, "Ollama template overrides the embedded template",
                "Ollama uses its own template layer instead of the GGUF's chat template. Both were scanned; the Ollama layer is the one that runs.",
                "ollama template layer"));
        return report;
    }

    /// <summary>Newer Ollama models can use a built-in renderer/parser instead of a template layer (rule O005).</summary>
    static void CheckOllamaConfig(string modelsDir, string? digest, ScanReport report)
    {
        if (digest is null || !DigestRegex().IsMatch(digest))
            return;
        var blob = Path.Combine(modelsDir, "blobs", digest.Replace(':', '-'));
        if (!File.Exists(blob) || new FileInfo(blob).Length > MaxTextLayerBytes)
            return;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(blob));
            var names = new[] { "renderer", "parser" }
                .Where(n => doc.RootElement.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String && v.GetString()!.Length > 0)
                .Select(n => $"{n} '{doc.RootElement.GetProperty(n).GetString()}'")
                .ToList();
            if (names.Count > 0)
                report.Findings.Add(new Finding("O005", Severity.Info, "Ollama formats prompts with built-in code",
                    $"This model uses Ollama's {string.Join(" and ", names)} instead of (or as well as) a template layer, so part of the prompt formatting is not on disk to review.",
                    "ollama config"));
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
        }
    }

    /// <summary>The template layer of an installed Ollama model ("llama3.2:1b", "user/model"), or null.</summary>
    public static string? FindOllamaTemplate(string name)
    {
        var wanted = name.Contains(':') ? name : name + ":latest";
        foreach (var dir in OllamaModelDirs())
        {
            var manifests = Path.Combine(dir, "manifests");
            foreach (var manifest in Directory.EnumerateFiles(manifests, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }))
            {
                if (!string.Equals(OllamaName(manifests, manifest), wanted, StringComparison.OrdinalIgnoreCase))
                    continue;
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(manifest));
                    var digest = doc.RootElement.GetProperty("layers").EnumerateArray()
                        .Where(l => l.GetProperty("mediaType").GetString() == TemplateMediaType)
                        .Select(l => l.GetProperty("digest").GetString())
                        .FirstOrDefault(d => d is not null && DigestRegex().IsMatch(d));
                    var blob = digest is null ? null : Path.Combine(dir, "blobs", digest.Replace(':', '-'));
                    return blob is not null && File.Exists(blob) && new FileInfo(blob).Length <= MaxTextLayerBytes ? File.ReadAllText(blob) : null;
                }
                catch (Exception ex) when (ex is IOException or JsonException or KeyNotFoundException or InvalidOperationException)
                {
                    return null;
                }
            }
        }
        return null;
    }

    static string? ReadTextLayer(string blob, ScanReport report, string what)
    {
        var size = new FileInfo(blob).Length;
        if (size > MaxTextLayerBytes)
        {
            report.Findings.Add(new Finding("O004", Severity.Medium, $"Oversized Ollama {what} layer", $"The {what} layer is {size:N0} bytes and was not analysed.", blob));
            return null;
        }
        return File.ReadAllText(blob);
    }

    /// <summary>Turns manifests/registry.ollama.ai/library/llama3/latest into "llama3:latest".</summary>
    static string OllamaName(string manifestsDir, string manifestPath)
    {
        var parts = Path.GetRelativePath(manifestsDir, manifestPath).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (parts.Length != 4)
            return string.Join('/', parts);
        var (host, ns, model, tag) = (parts[0], parts[1], parts[2], parts[3]);
        var name = host == "registry.ollama.ai" ? (ns == "library" ? model : $"{ns}/{model}") : $"{host}/{ns}/{model}";
        return $"{name}:{tag}";
    }
}
