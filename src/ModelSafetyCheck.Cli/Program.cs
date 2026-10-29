using System.CommandLine;
using System.Text.Json;
using System.Text.Json.Serialization;
using ModelSafetyCheck.Audit;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Hub;
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
        Description = "Output format: text, json, jsonl (streaming) or sarif.",
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

    static readonly Option<string?> ClassifierOption = new("--classifier")
    {
        Description = "Also score template and system-prompt text with the local prompt-injection classifier (rule T015). Optional path; default ~/.modelcheck/classifier.",
        Arity = ArgumentArity.ZeroOrOne,
        Recursive = true,
    };

    public static int Main(string[] args)
    {
        FormatOption.AcceptOnlyFromAmong("text", "json", "jsonl", "sarif");

        var pathsArgument = new Argument<string[]>("paths")
        {
            Description = "Model files or directories: .gguf, .safetensors, pickle checkpoints (.bin/.pt/.pth/.ckpt/.pkl), tokenizer_config.json, chat_template.jinja.",
            Arity = ArgumentArity.OneOrMore,
        };
        var scan = new Command("scan", "Scan model files: GGUF structure/metadata/templates, safetensors headers, pickle imports, Hugging Face chat templates.") { pathsArgument };
        scan.SetAction(result => Run(result, ScanPaths(result.GetValue(pathsArgument)!)));

        var onlineOption = new Option<bool>("--online") { Description = "Look up each model's Hugging Face repo: publisher, lineage, and whether the file is still the published one." };
        var hashOption = new Option<bool>("--hash") { Description = "With --online: verify the sha256 of each file (reads every model in full)." };
        var local = new Command("local", "Scan every model installed in Ollama, LM Studio and the llama.cpp / Hugging Face caches, including runner template overrides.")
        {
            onlineOption, hashOption,
        };
        local.SetAction(result => Run(result, LocalScans(result.GetValue(onlineOption), result.GetValue(hashOption))));

        var agentDirOption = new Option<string?>("--agent-dir") { Description = "An agent's working directory to check for readable secrets (layer 5)." };
        var probeOption = new Option<bool>("--probe") { Description = "Test whether exposed model servers answer this machine's own LAN addresses without authentication." };
        var mcpOption = new Option<string[]>("--mcp-config") { Description = "Extra MCP config files (with an \"mcpServers\" object) to check, e.g. another client's." };
        var audit = new Command("audit", "Audit this machine: installed models, runner versions, network exposure, Docker, and (optionally) an agent's directory.")
        {
            agentDirOption, probeOption, mcpOption,
        };
        audit.SetAction(result => Run(result, AuditScans(new AuditOptions(result.GetValue(agentDirOption), result.GetValue(probeOption), result.GetValue(mcpOption)))));

        var repoArgument = new Argument<string[]>("repos") { Description = "Hugging Face repos ('org/name' or URLs) or Ollama models ('ollama:llama3.2:1b', 'ollama:user/model').", Arity = ArgumentArity.OneOrMore };
        var maxFilesOption = new Option<int>("--max-files") { Description = "GGUF files to check per repo (spread across sizes).", DefaultValueFactory = _ => 6 };
        var allFilesOption = new Option<bool>("--all-files") { Description = "Check every supported weight file, including all GGUF shards." };
        var budgetOption = new Option<int>("--budget-mb") { Description = "Maximum MiB to download per GGUF header.", DefaultValueFactory = _ => 64 };
        var repo = new Command("repo", "Check a Hugging Face repo or Ollama registry model before downloading: lure files, model card, publisher, lineage, templates, and weight-file headers (without downloading the weights).")
        {
            repoArgument, maxFilesOption, allFilesOption, budgetOption,
        };
        repo.SetAction(result => Run(result, RepoScans(result.GetValue(repoArgument)!,
            new RepoScanOptions(result.GetValue(maxFilesOption), result.GetValue(allFilesOption), result.GetValue(budgetOption)))));

        var baselineOption = new Option<bool>("--baseline") { Description = "Record the current templates as the baseline and exit." };
        var updateOption = new Option<bool>("--update") { Description = "After reporting changes, accept them as the new baseline." };
        var storeOption = new Option<string>("--store") { Description = "Snapshot file.", DefaultValueFactory = _ => TemplateWatch.DefaultStorePath };
        var logOption = new Option<string?>("--log") { Description = "Append output to this file instead of the console (for scheduled runs)." };
        var printScheduleOption = new Option<bool>("--print-schedule") { Description = "Show how an hourly check would be scheduled on this OS, without changing anything." };
        var installScheduleOption = new Option<bool>("--install-schedule") { Description = "Schedule an hourly check with the OS scheduler." };
        var notifyOption = new Option<bool>("--notify") { Description = "Show a desktop notification when a template changes without a model update." };
        var watch = new Command("watch", "Detect templates or system prompts that change without a model update (e.g. rewritten through the runner's API).")
        {
            baselineOption, updateOption, storeOption, logOption, notifyOption, printScheduleOption, installScheduleOption,
        };
        watch.SetAction(result => Watch(result, result.GetValue(storeOption)!, result.GetValue(baselineOption), result.GetValue(updateOption),
            result.GetValue(logOption), result.GetValue(notifyOption), result.GetValue(printScheduleOption), result.GetValue(installScheduleOption)));

        var explainPath = new Argument<string>("path") { Description = "A .gguf file, a tokenizer_config.json, or a template file (.jinja)." };
        var messagesOption = new Option<string?>("--messages") { Description = "JSON file with your own conversation ([{\"role\": ..., \"content\": ...}])." };
        var explain = new Command("explain", "Render a chat template in a sandbox: show exactly what the model receives, and what changes when trigger phrases or dates are present.")
        {
            explainPath, messagesOption,
        };
        explain.SetAction(result => ExplainCommand.Run(result.GetValue(explainPath)!, result.GetValue(messagesOption), Console.Out));

        var dirOption = new Option<string>("--dir") { Description = "Where the classifier lives.", DefaultValueFactory = _ => Classifier.PromptInjectionClassifier.DefaultDirectory };
        var repoOption = new Option<string>("--repo") { Description = "Hugging Face repo with an onnx/ export.", DefaultValueFactory = _ => ClassifierCommand.DefaultRepo };
        var download = new Command("download", "Download the prompt-injection classifier (~700 MB, Apache-2.0) and verify its sha256.") { dirOption, repoOption };
        download.SetAction(result => ClassifierCommand.Download(result.GetValue(repoOption)!, result.GetValue(dirOption)!, Console.Out));
        var textArgument = new Argument<string>("text") { Description = "Text to score." };
        var test = new Command("test", "Score a piece of text with the classifier.") { textArgument, dirOption };
        test.SetAction(result => ClassifierCommand.Test(result.GetValue(dirOption)!, result.GetValue(textArgument)!, Console.Out));
        var classifier = new Command("classifier", "Optional local ML check for prompt-injection text (rule T015).") { download, test };

        var root = new RootCommand("modelcheck: scan local AI models and setups for malicious files, templates and configuration.")
        {
            scan, local, audit, repo, watch, explain, classifier, BatchCommand.Create(), FormatOption, MinSeverityOption, DumpTemplateOption, NoColorOption, ClassifierOption,
        };
        return root.Parse(args).Invoke();
    }

    static int Watch(ParseResult result, string store, bool baseline, bool update, string? log, bool notify, bool printSchedule, bool installSchedule)
    {
        if (printSchedule || installSchedule)
        {
            var plan = WatchSchedule.Plan();
            Console.WriteLine(WatchSchedule.Describe(plan));
            if (!installSchedule)
                return ExitClean;
            var error = WatchSchedule.Install(plan);
            Console.WriteLine(error is null ? "\nScheduled." : $"\nFailed: {error}");
            return error is null ? ExitClean : ExitError;
        }

        TextWriter? logWriter = null;
        if (log is not null)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(log))!);
            logWriter = new StreamWriter(log, append: true) { AutoFlush = true };
            logWriter.WriteLine($"\n===== modelcheck watch {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz} =====");
            Console.SetOut(logWriter);
        }

        try
        {
            var reports = LocalModels.ScanAll().ToList();
            var current = TemplateWatch.Capture(reports);
            var previous = baseline ? null : TemplateWatch.Load(store);
            if (previous is null)
            {
                TemplateWatch.Save(current, store);
                Console.WriteLine($"Saved a baseline of {current.Models.Count} model(s) and {current.Models.Sum(m => m.ContentHashes.Count)} template/system prompt(s) to {store}.");
                return ExitClean;
            }

            var drift = TemplateWatch.Compare(previous, current);
            var changedTargets = drift.Findings.Where(f => f.RuleId is "W001" or "W002").Select(f => f.Location).ToHashSet();
            if (update)
                TemplateWatch.Save(current, store);

            var rewritten = drift.Findings.Where(f => f.RuleId == "W001").Select(f => f.Location).Distinct().ToList();
            if (notify && rewritten.Count > 0 && !DesktopNotifier.Notify("modelcheck: model template changed",
                    $"{rewritten.Count} model(s) changed without a model update: {string.Join(", ", rewritten)}"))
                Console.WriteLine("(Desktop notification could not be shown.)");

            return Run(result, reports.Where(r => changedTargets.Contains(r.Target)).Append(drift));
        }
        finally
        {
            logWriter?.Dispose();
        }
    }

    static IEnumerable<ScanReport> ScanPaths(IEnumerable<string> paths)
    {
        foreach (var path in paths)
        {
            if (Directory.Exists(path))
            {
                foreach (var file in Directory.EnumerateFiles(path, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }).Where(ModelScanner.IsScannable))
                    yield return ModelScanner.ScanAnyFile(file);
            }
            else if (File.Exists(path))
                yield return ModelScanner.ScanAnyFile(path);
            else
                yield return new ScanReport { Target = path, Kind = "gguf", Error = "File or directory not found." };
        }
    }

    static IEnumerable<ScanReport> LocalScans(bool online, bool hash)
    {
        if (!online)
        {
            foreach (var report in LocalModels.ScanAll())
                yield return report;
            yield break;
        }
        using var client = new HuggingFaceClient();
        var cache = new Dictionary<string, HfModelInfo?>();
        foreach (var report in LocalModels.ScanAll())
        {
            LocalProvenance.Check(client, [report], hash, cache);
            yield return report;
        }
    }

    static IEnumerable<ScanReport> RepoScans(IEnumerable<string> repos, RepoScanOptions options)
    {
        using var client = new HuggingFaceClient();
        foreach (var repo in repos)
            foreach (var report in OllamaRegistryScanner.IsOllamaName(repo) ? OllamaRegistryScanner.Scan(client, repo, options) : RepoScanner.Scan(client, repo, options))
                yield return report;
    }

    /// <summary>Model scans first (their results feed the audit's risk rating), then the machine audit.</summary>
    static IEnumerable<ScanReport> AuditScans(AuditOptions options)
    {
        var models = new List<ScanReport>();
        foreach (var report in LocalModels.ScanAll())
        {
            models.Add(report);
            yield return report;
        }
        yield return MachineAudit.Run(options, models);
    }

    internal static int Run(ParseResult result, IEnumerable<ScanReport> scans)
    {
        if (result.GetResult(ClassifierOption) is not null)
        {
            var directory = result.GetValue(ClassifierOption) is { Length: > 0 } dir ? dir : Classifier.PromptInjectionClassifier.DefaultDirectory;
            TextClassification.Classifier = Classifier.PromptInjectionClassifier.TryLoad(directory, out var error);
            if (error is not null)
            {
                Console.Error.WriteLine(error);
                return ExitError;
            }
        }

        var minSeverity = result.GetValue(MinSeverityOption);
        var reports = new List<ScanReport>();
        var format = result.GetValue(FormatOption);
        var text = new TextReporter(Console.Out, !result.GetValue(NoColorOption) && !Console.IsOutputRedirected && Environment.GetEnvironmentVariable("NO_COLOR") is null);
        Severity? max = null;
        long reportCount = 0, errorCount = 0;
        var severityCounts = new long[Enum.GetValues<Severity>().Length];
        var compactJson = new CliJsonContext(new JsonSerializerOptions(CliJsonContext.Default.Options) { WriteIndented = false });

        foreach (var report in scans)
        {
            if (report.MaxSeverity is { } severity && (max is null || severity > max))
                max = severity;
            report.Findings.RemoveAll(f => f.Severity < minSeverity);
            report.Findings.Sort((a, b) => b.Severity.CompareTo(a.Severity));
            reportCount++;
            if (report.Error is not null) errorCount++;
            foreach (var finding in report.Findings) severityCounts[(int)finding.Severity]++;
            if (format is "json" or "sarif") reports.Add(report);
            if (format == "text")
                text.Write(report, result.GetValue(DumpTemplateOption));
            else if (format == "jsonl")
                Console.WriteLine(JsonSerializer.Serialize(report, compactJson.ScanReport));
        }

        if (format == "sarif")
            Console.WriteLine(SarifWriter.Write(reports));
        else if (format == "json")
            Console.WriteLine(JsonSerializer.Serialize(reports, CliJsonContext.Default.ListScanReport));
        else if (format == "text")
            text.WriteSummary(reportCount, errorCount, severityCounts);

        if (errorCount > 0) return ExitError;
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
