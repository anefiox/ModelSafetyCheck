using System.CommandLine;
using System.Text.Json;
using System.Text.Json.Serialization;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Local;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Cli;

public static class Program
{
    public const int ExitClean = 0;
    public const int ExitWarnings = 1;
    public const int ExitHighRisk = 2;
    public const int ExitError = 3;

    static readonly Option<string> FormatOption = new("--format", "-f")
    {
        Description = "Output format: text or json.",
        DefaultValueFactory = _ => "text",
        Recursive = true,
    };

    static readonly Option<Severity> MinSeverityOption = new("--min-severity")
    {
        Description = "Hide findings below this severity (info, low, medium, high, critical).",
        DefaultValueFactory = _ => Severity.Info,
        Recursive = true,
    };

    static readonly Option<bool> DumpTemplateOption = new("--dump-template")
    {
        Description = "Print every extracted chat template.",
        Recursive = true,
    };

    static readonly Option<bool> NoColorOption = new("--no-color")
    {
        Description = "Disable coloured output.",
        Recursive = true,
    };

    public static int Main(string[] args)
    {
        FormatOption.AcceptOnlyFromAmong("text", "json");

        var pathsArgument = new Argument<string[]>("paths")
        {
            Description = "GGUF files or directories (searched recursively for *.gguf).",
            Arity = ArgumentArity.OneOrMore,
        };
        var scan = new Command("scan", "Scan GGUF files: structure, metadata, tokenizer and chat templates.") { pathsArgument };
        scan.SetAction(result => Run(result, ScanPaths(result.GetValue(pathsArgument)!)));

        var local = new Command("local", "Scan every model installed in Ollama and LM Studio, including Ollama's own template layers.");
        local.SetAction(result => Run(result, LocalModels.ScanOllama().Concat(LocalModels.ScanLmStudio())));

        var root = new RootCommand("modelcheck: scan local AI models and setups for malicious files, templates and configuration.")
        {
            scan, local, FormatOption, MinSeverityOption, DumpTemplateOption, NoColorOption,
        };
        return root.Parse(args).Invoke();
    }

    static IEnumerable<ScanReport> ScanPaths(IEnumerable<string> paths)
    {
        foreach (var path in paths)
        {
            if (Directory.Exists(path))
            {
                foreach (var file in Directory.EnumerateFiles(path, "*.gguf", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }))
                    yield return ModelScanner.ScanFile(file);
            }
            else if (File.Exists(path))
                yield return ModelScanner.ScanFile(path);
            else
                yield return new ScanReport { Target = path, Kind = "gguf", Error = "File or directory not found." };
        }
    }

    static int Run(ParseResult result, IEnumerable<ScanReport> scans)
    {
        var minSeverity = result.GetValue(MinSeverityOption);
        var reports = new List<ScanReport>();
        var json = result.GetValue(FormatOption) == "json";
        var text = new TextReporter(Console.Out, !result.GetValue(NoColorOption) && !Console.IsOutputRedirected && Environment.GetEnvironmentVariable("NO_COLOR") is null);

        foreach (var report in scans)
        {
            report.Findings.RemoveAll(f => f.Severity < minSeverity);
            report.Findings.Sort((a, b) => b.Severity.CompareTo(a.Severity));
            reports.Add(report);
            if (!json)
                text.Write(report, result.GetValue(DumpTemplateOption));
        }

        if (json)
            Console.WriteLine(JsonSerializer.Serialize(reports, CliJsonContext.Default.ListScanReport));
        else
            text.WriteSummary(reports);

        if (reports.Any(r => r.Error is not null)) return ExitError;
        var max = reports.Select(r => r.MaxSeverity).Max();
        return max switch
        {
            >= Severity.High => ExitHighRisk,
            >= Severity.Low => ExitWarnings,
            _ => ExitClean,
        };
    }
}

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, UseStringEnumConverter = true)]
[JsonSerializable(typeof(List<ScanReport>))]
internal sealed partial class CliJsonContext : JsonSerializerContext;
