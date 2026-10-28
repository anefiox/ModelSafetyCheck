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

    public ModelSummary? Summary { get; set; }
    public List<Finding> Findings { get; } = [];
    public List<ExtractedTemplate> Templates { get; } = [];

    /// <summary>Set when the target could not be scanned at all (I/O error, missing file).</summary>
    public string? Error { get; set; }

    public Severity? MaxSeverity => Findings.Count == 0 ? null : Findings.Max(f => f.Severity);
}

public static class ModelScanner
{
    static readonly IGgufRule[] GgufRules = [new StructuralRules(), new MetadataRules(), new TokenizerRules()];

    public static ScanReport ScanFile(string path, string kind = "gguf", string? target = null)
    {
        var report = new ScanReport { Target = target ?? path, Kind = kind };
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20);
            ScanGguf(stream, report);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            report.Error = ex.Message;
        }
        return report;
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
        report.Findings.Add(new Finding("T001", Severity.Info, "Chat template found",
            $"{template.Length:N0} characters, {dialect}, sha256 {extracted.Sha256}. Use --dump-template to read it.", location));
        report.Findings.AddRange(TemplateAnalyzer.Analyze(template, dialect, location));
    }

    public static void ScanSystemPrompt(ScanReport report, string text, string location) =>
        report.Findings.AddRange(TemplateAnalyzer.AnalyzePlainText(text, location));

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

    static string Sha256(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}
