using System.Security.Cryptography;
using System.Text;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Jinja;

namespace ModelSafetyCheck.Rules;

public sealed record ModelSummary(
    uint Version,
    string? Architecture,
    string? Name,
    int TensorCount,
    int MetadataCount,
    long FileSize,
    IReadOnlyList<string> BaseModels);

public sealed record ExtractedTemplate(string Location, TemplateDialect Dialect, string Sha256, int Length, string Text);

public sealed class ScanReport
{
    public required string Target { get; init; }

    /// <summary>"gguf", "ollama", "lmstudio".</summary>
    public required string Kind { get; init; }

    /// <summary>Local file path, when the target is a file on disk.</summary>
    public string? Path { get; init; }

    /// <summary>Identifies the model weights (Ollama blob digest, or size and modification time of a file). Used by `watch`.</summary>
    public string? Fingerprint { get; set; }

    /// <summary>sha256 of every template and system prompt, by location. Used by `watch` to spot rewrites.</summary>
    public Dictionary<string, string> ContentHashes { get; init; } = [];

    public ModelSummary? Summary { get; set; }
    public List<Finding> Findings { get; init; } = [];
    public List<ExtractedTemplate> Templates { get; init; } = [];

    /// <summary>Set when the target could not be scanned at all (I/O error, missing file).</summary>
    public string? Error { get; set; }

    public Severity? MaxSeverity => Findings.Count == 0 ? null : Findings.Max(f => f.Severity);
}

public static class ModelScanner
{
    public const int MaxTemplateFileBytes = 4 << 20;
    static readonly IGgufRule[] GgufRules = [new StructuralRules(), new MetadataRules(), new TokenizerRules()];

    public static ScanReport ScanFile(string path, string kind = "gguf", string? target = null)
    {
        var report = new ScanReport { Target = target ?? path, Kind = kind, Path = path };
        try
        {
            var info = new FileInfo(path);
            report.Fingerprint = $"size:{info.Length};mtime:{info.LastWriteTimeUtc:O}";
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20);
            ScanGguf(stream, report);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            report.Error = ex.Message;
        }
        return report;
    }

    /// <summary>Plain template files: Jinja (.jinja, .j2) and Go text/template as used by Ollama (.tmpl, .gotmpl).</summary>
    static readonly HashSet<string> TemplateExtensions = new(StringComparer.OrdinalIgnoreCase) { ".jinja", ".j2", ".tmpl", ".gotmpl" };

    /// <summary>File types `scan` understands: GGUF, safetensors, pickle checkpoints and Hugging Face template files.</summary>
    public static bool IsScannable(string path)
    {
        var name = System.IO.Path.GetFileName(path);
        var ext = System.IO.Path.GetExtension(path);
        return ext.Equals(".gguf", StringComparison.OrdinalIgnoreCase) || ext.Equals(".safetensors", StringComparison.OrdinalIgnoreCase) || ext.Equals(".onnx", StringComparison.OrdinalIgnoreCase) ||
               PickleScanner.Extensions.Contains(ext) || name is "tokenizer_config.json" or "chat_template.json" || TemplateExtensions.Contains(ext);
    }

    /// <summary>Scans any supported file by type.</summary>
    public static ScanReport ScanAnyFile(string path)
    {
        var ext = System.IO.Path.GetExtension(path);
        var name = System.IO.Path.GetFileName(path);
        if (ext.Equals(".gguf", StringComparison.OrdinalIgnoreCase))
            return ScanFile(path);

        var kind = ext.Equals(".safetensors", StringComparison.OrdinalIgnoreCase) ? "safetensors"
            : ext.Equals(".onnx", StringComparison.OrdinalIgnoreCase) ? "onnx"
            : PickleScanner.Extensions.Contains(ext) ? "pickle" : "template-file";
        var report = new ScanReport { Target = path, Kind = kind, Path = path };
        try
        {
            if (kind == "template-file")
            {
                ScanTemplateFile(path, name, report);
                return report;
            }
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20);
            var info = new FileInfo(path);
            report.Fingerprint = $"size:{info.Length};mtime:{info.LastWriteTimeUtc:O}";
            if (kind == "safetensors") SafetensorsScanner.Scan(stream, report);
            else if (kind == "onnx") OnnxScanner.Scan(stream, report, path);
            else PickleScanner.Scan(stream, report);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidDataException)
        {
            report.Error = ex.Message;
        }
        return report;
    }

    /// <summary>chat_template.jinja or the chat_template in tokenizer_config.json: what transformers and vLLM render.</summary>
    static void ScanTemplateFile(string path, string name, ScanReport report)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length > MaxTemplateFileBytes)
            throw new InvalidDataException($"Template/config file exceeds the {MaxTemplateFileBytes}-byte limit.");
        using var reader = new StreamReader(stream);
        var buffer = new char[MaxTemplateFileBytes + 1];
        var count = reader.ReadBlock(buffer, 0, buffer.Length);
        if (count > MaxTemplateFileBytes)
            throw new InvalidDataException("Template/config file exceeds the text limit.");
        ScanTemplateText(new string(buffer, 0, count), name, report);
    }

    /// <summary>Shared validation for downloaded and local template/config files.</summary>
    public static void ScanTemplateText(string text, string name, ScanReport report)
    {
        if (text.Length > MaxTemplateFileBytes)
        {
            report.Error = "Template/config text exceeds the size limit.";
            return;
        }
        var ext = System.IO.Path.GetExtension(name);
        if (TemplateExtensions.Contains(ext))
        {
            var dialect = ext.Equals(".tmpl", StringComparison.OrdinalIgnoreCase) || ext.Equals(".gotmpl", StringComparison.OrdinalIgnoreCase)
                ? TemplateDialect.GoTemplate
                : TemplateDialect.Jinja;
            ScanTemplate(report, text, dialect, name);
            return;
        }
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(text);
            if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object)
                throw new InvalidDataException("Template/config JSON must be an object.");
            if (!doc.RootElement.TryGetProperty("chat_template", out var t))
                return;
            if (t.ValueKind == System.Text.Json.JsonValueKind.String)
                ScanTemplate(report, t.GetString()!, TemplateDialect.Jinja, $"{name}:chat_template");
            else if (t.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                foreach (var item in t.EnumerateArray())
                {
                    if (item.ValueKind != System.Text.Json.JsonValueKind.Object ||
                        !item.TryGetProperty("template", out var tt) || tt.ValueKind != System.Text.Json.JsonValueKind.String ||
                        !item.TryGetProperty("name", out var n) || n.ValueKind != System.Text.Json.JsonValueKind.String)
                        throw new InvalidDataException("Each chat_template entry must have string name and template fields.");
                    ScanTemplate(report, tt.GetString()!, TemplateDialect.Jinja, $"{name}:chat_template.{n.GetString()}");
                }
            }
            else
                throw new InvalidDataException("chat_template must be a string or a list of named templates.");
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or InvalidDataException)
        {
            report.Error = $"{name}: {ex.Message}";
        }
    }

    public static ScanReport ScanStream(Stream stream, string target)
    {
        var report = new ScanReport { Target = target, Kind = "gguf" };
        ScanGguf(stream, report);
        return report;
    }

    /// <summary>Scans a GGUF from a seekable stream into an existing report.</summary>
    public static void ScanGguf(Stream stream, ScanReport report, string locationPrefix = "")
    {
        var file = GgufParser.Parse(stream);
        var context = new GgufScanContext(file, stream);

        report.Summary ??= Summarize(file);
        report.Findings.AddRange(file.ParseFindings.Select(f => Prefix(f, locationPrefix)));
        foreach (var rule in GgufRules)
            report.Findings.AddRange(rule.Check(context).Select(f => Prefix(f, locationPrefix)));

        foreach (var kv in file.Metadata.Where(k => TemplateRules.IsTemplateKey(k.Key)))
        {
            if (kv.Value is string template)
                ScanTemplate(report, template, TemplateDialect.Jinja, $"{locationPrefix}kv:{kv.Key}");
        }
    }

    public static void ScanTemplate(ScanReport report, string template, TemplateDialect dialect, string location)
    {
        var extracted = new ExtractedTemplate(location, dialect, Sha256(template), template.Length, template);
        report.Templates.Add(extracted);
        report.ContentHashes[location] = extracted.Sha256;
        report.Findings.Add(new Finding("T001", Severity.Info, "Chat template found",
            $"{template.Length:N0} characters, {dialect}, sha256 {extracted.Sha256}. Use --dump-template to read it.", location));
        report.Findings.AddRange(AnalyzeTemplate(template, dialect, location));
    }

    /// <summary>
    /// Heuristic rules plus the known-template check. An exact match with an official template turns
    /// heuristic hits into Info: official templates contain phrases like "do not tell the user about
    /// function calls", and any injected text would break the exact match anyway.
    /// </summary>
    public static List<Finding> AnalyzeTemplate(string template, TemplateDialect dialect, string location)
    {
        var findings = AddRenderedEvidence(template, dialect, location, TemplateAnalyzer.Analyze(template, dialect, location), out var probeAdded);
        if (TextClassification.Classifier is not null)
        {
            // Measured on the top 1,000 GGUF repos, the classifier flags ordinary instructions (tool formats, personas) in
            // 13% of templates, so on its own it is only listed. It corroborates a trigger or an injected-looking copy.
            var corroborated = findings.Any(f => f.RuleId is "T005" or "T013" && f.Severity >= Severity.Medium);
            var classified = TextClassification.Check(TextClassification.TextToClassify(template, dialect, probeAdded), location, "template")
                .Select(f => corroborated ? f : f with { Severity = Severity.Info }).ToList();
            findings.AddRange(classified);
        }
        var known = dialect == TemplateDialect.Jinja ? KnownTemplateCheck.Check(template, location) : null;
        if (known is null)
            return findings;

        if (known is { RuleId: "T010", Severity: Severity.Medium })
            findings = findings.Select(f => f is { RuleId: "T015", Severity: Severity.Info } ? f with { Severity = Severity.Medium } : f).ToList();

        if (known.Severity == Severity.Info && known.Title.StartsWith("Matches the official", StringComparison.Ordinal))
            findings = findings
                .Select(f => f.Severity > Severity.Info
                    ? f with { Severity = Severity.Info, Title = f.Title + " (in official template)", Detail = $"Was {f.Severity}; this text is part of the official template.\n{f.Detail}" }
                    : f)
                .ToList();
        findings.Add(known);
        return findings;
    }

    /// <summary>
    /// Renders the template in the sandbox with trigger probes (T013). Confirmed payloads raise the static
    /// trigger finding (T005) to High; a template that cannot be rendered is noted (T014).
    /// </summary>
    static List<Finding> AddRenderedEvidence(string template, TemplateDialect dialect, string location, List<Finding> findings, out List<string> probeAdded)
    {
        var explanation = TemplateExplainer.Explain(template, new ExplainOptions { Dialect = dialect });
        probeAdded = explanation.Probes.SelectMany(p => p.Added).Select(a => a.Replace("«probe»", "")).ToList();
        if (explanation.Error is not null)
        {
            findings.Add(new Finding("T014", Severity.Info, "Template could not be rendered in the sandbox",
                $"{explanation.Error}. Trigger probes were skipped; the static checks above still apply.", location));
            return findings;
        }

        var rendered = TemplateExplainer.Findings(explanation, location).ToList();
        findings.AddRange(rendered);
        if (rendered.Any(f => f.Severity >= Severity.High))
            findings = findings.Select(f => f is { RuleId: "T005", Severity: Severity.Medium }
                ? f with { Severity = Severity.High, Detail = f.Detail + "\nRaised to High: rendering confirmed that a trigger adds text (T013)." }
                : f).ToList();
        return findings;
    }

    public static void ScanSystemPrompt(ScanReport report, string text, string location)
    {
        report.ContentHashes[location] = Sha256(text);
        report.Findings.AddRange(TemplateAnalyzer.AnalyzePlainText(text, location));
        if (TextHeuristics.CountWords(text) >= 6)
            report.Findings.AddRange(TextClassification.Check([text], location, "system prompt"));
    }

    static ModelSummary Summarize(GgufFile file)
    {
        var baseModels = new List<string>();
        var count = file.GetInteger("general.base_model.count") ?? 0;
        for (var i = 0; i < Math.Min(count, 16); i++)
        {
            var name = file.GetString($"general.base_model.{i}.name");
            var org = file.GetString($"general.base_model.{i}.organization");
            var repo = file.GetString($"general.base_model.{i}.repo_url");
            var parts = new[] { org, name, repo is null ? null : $"({repo})" }.Where(p => !string.IsNullOrEmpty(p));
            baseModels.Add(string.Join(" ", parts));
        }
        return new ModelSummary(file.Version, file.GetString("general.architecture"), file.GetString("general.name"),
            file.Tensors.Count, file.Metadata.Count, file.FileLength, baseModels);
    }

    static Finding Prefix(Finding finding, string prefix) =>
        prefix.Length == 0 ? finding : finding with { Location = finding.Location is null ? prefix.TrimEnd(' ', '/') : prefix + finding.Location };

    public static string Sha256(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}
