using System.CommandLine;
using System.Text.Json;
using System.Text.Json.Serialization;
using ModelSafetyCheck.Audit;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Hub;
using ModelSafetyCheck.Local;
using ModelSafetyCheck.Rules;
using ModelSafetyCheck.Rules.Policy;

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

    static readonly Option<string?> PolicyOption = new("--policy")
    {
        Description = "Policy file (.modelcheck.yml/.yaml/.json). Default: the first one found in the current directory or its parents.",
        Recursive = true,
    };

    static readonly Option<bool> NoPolicyOption = new("--no-policy")
    {
        Description = "Ignore any policy file.",
        Recursive = true,
    };

    static readonly Option<string?> BaselineFileOption = new("--baseline-file")
    {
        Description = "Baseline of known findings; only new findings count. Overrides the policy's 'baseline'.",
        Recursive = true,
    };

    static readonly Option<string?> WriteBaselineOption = new("--write-baseline")
    {
        Description = "Record this run's findings (except suppressed ones) as a baseline file.",
        Recursive = true,
    };

    static readonly Option<bool> ShowSuppressedOption = new("--show-suppressed")
    {
        Description = "In text output, also show suppressed findings and findings already in the baseline.",
        Recursive = true,
    };

    static readonly Option<string?> SaveOption = new("--save")
    {
        Description = "Also save this run (all findings, as JSON) to a timestamped file. Optional directory; default ~/.modelcheck/reports.",
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

        var repoArgument = new Argument<string[]>("repos") { Description = "Hugging Face repos ('org/name' or URLs) or Ollama models ('ollama:llama3.2:1b', 'ollama:user/model').", Arity = ArgumentArity.ZeroOrMore };
        var maxFilesOption = new Option<int>("--max-files") { Description = "GGUF files to check per repo (spread across sizes).", DefaultValueFactory = _ => 6 };
        var allFilesOption = new Option<bool>("--all-files") { Description = "Check every supported weight file, including all GGUF shards." };
        var budgetOption = new Option<int>("--budget-mb") { Description = "Maximum MiB to download per GGUF header.", DefaultValueFactory = _ => 64 };
        var repoLineageOption = new Option<bool>("--lineage") { Description = "Also compare one GGUF's weights with the base model the repo claims to quantize (samples rows; ~20-50 MiB)." };
        var repo = new Command("repo", "Check a Hugging Face repo or Ollama registry model before downloading: lure files, model card, publisher, lineage, templates, and weight-file headers (without downloading the weights).")
        {
            repoArgument, maxFilesOption, allFilesOption, budgetOption, repoLineageOption,
        };
        var discover = DiscoverOptions.AddTo(repo);
        repo.SetAction(result =>
        {
            var options = new RepoScanOptions(result.GetValue(maxFilesOption), result.GetValue(allFilesOption), result.GetValue(budgetOption)) { Lineage = result.GetValue(repoLineageOption) };
            var repos = result.GetValue(repoArgument) ?? [];
            if (!result.GetValue(discover.Enabled))
                return repos.Length > 0 ? Run(result, RepoScans(repos, options)) : Usage("Name at least one repo, or use --discover.");
            if (repos.Length > 0)
                return Usage("Use either repo names or --discover, not both.");
            return discover.TryCreate(result, out var query, out var state, out var error)
                ? Run(result, DiscoverOptions.Scans(query, state, result.GetValue(discover.Rescan), options))
                : Usage(error);
        });

        var lineageCandidate = new Argument<string>("model") { Description = "The GGUF to check: a local file, hf:org/repo/file.gguf, or an HTTPS URL." };
        var lineageBase = new Option<string>("--base") { Description = "The GGUF it claims to be a quantization of (ideally the official F16/BF16/Q8_0): same forms as the model.", Required = true };
        var lineageBudget = new Option<int>("--budget-mb") { Description = "Maximum MiB to download per remote file (headers plus sampled rows).", DefaultValueFactory = _ => 256 };
        var lineageSample = new Option<int>("--sample") { Description = "Values compared per tensor (whole rows from the middle of each tensor).", DefaultValueFactory = _ => 16384 };
        var lineage = new Command("lineage", "Check that a GGUF really carries its claimed base model's weights: compares sampled rows of every tensor against quantization noise.")
        {
            lineageCandidate, lineageBase, lineageBudget, lineageSample,
        };
        lineage.SetAction(result => Run(result, LineageScan(result.GetValue(lineageCandidate)!, result.GetValue(lineageBase)!,
            result.GetValue(lineageBudget), result.GetValue(lineageSample))));

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
            scan, local, audit, repo, lineage, watch, explain, classifier, BatchCommand.Create(), PolicyCommand.Create(), BaselineCommand(), ExportCommand.Create(),
            FormatOption, MinSeverityOption, DumpTemplateOption, NoColorOption, ClassifierOption,
            PolicyOption, NoPolicyOption, BaselineFileOption, WriteBaselineOption, ShowSuppressedOption, SaveOption,
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

    static int Usage(string message)
    {
        Console.Error.WriteLine(message);
        return ExitError;
    }

    static IEnumerable<ScanReport> LineageScan(string candidate, string @base, int budgetMiB, int sample)
    {
        if (budgetMiB <= 0 || sample <= 0)
        {
            yield return new ScanReport { Target = candidate, Kind = "lineage", Error = "--budget-mb and --sample must be positive." };
            yield break;
        }
        using var client = new HuggingFaceClient();
        var progress = Console.IsErrorRedirected ? null : new Action<int, int>((done, total) =>
            Console.Error.Write(done == total ? "\r" + new string(' ', 40) + "\r" : $"\rComparing tensors {done}/{total}..."));
        yield return LineageSources.Check(client, candidate, @base, (long)budgetMiB << 20,
            new Rules.Lineage.LineageOptions { SampleValues = sample, Progress = progress });
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

    static Command BaselineCommand()
    {
        var file = new Argument<string>("file") { Description = "Baseline file to write." };
        var paths = new Argument<string[]>("paths") { Description = "Model files or directories to scan (as 'scan').", Arity = ArgumentArity.OneOrMore };
        var write = new Command("write", "Scan paths and record every finding as known, so later runs with this baseline only count new findings. " +
            "For other commands (local, repo, audit, batch) add --write-baseline <file>.") { file, paths };
        write.SetAction(result => Run(result, ScanPaths(result.GetValue(paths)!), result.GetValue(file)));
        return new Command("baseline", "Record known findings so CI only fails on new ones.") { write };
    }

    /// <summary>The policy for this run: --no-policy, --policy, or the first policy file above the current directory.</summary>
    internal static ModelPolicy ResolvePolicy(ParseResult result)
    {
        if (result.GetValue(NoPolicyOption)) return ModelPolicy.Default;
        var path = result.GetValue(PolicyOption) ?? ModelPolicy.Discover(Environment.CurrentDirectory);
        if (path is null) return ModelPolicy.Default;
        if (!File.Exists(path)) throw new PolicyException($"Policy file not found: {path}");
        try
        {
            return ModelPolicy.Load(path);
        }
        catch (PolicyException ex)
        {
            throw new PolicyException($"{path}: {ex.Message}");
        }
    }

    internal static int Run(ParseResult result, IEnumerable<ScanReport> scans) => Run(result, scans, null);

    static int Run(ParseResult result, IEnumerable<ScanReport> scans, string? writeBaseline)
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

        ModelPolicy policy;
        PolicyEngine engine;
        writeBaseline ??= result.GetValue(WriteBaselineOption);
        try
        {
            policy = ResolvePolicy(result);
            // Writing a baseline records everything, so an existing baseline is not applied to that run.
            var baselinePath = writeBaseline is null ? result.GetValue(BaselineFileOption) ?? policy.BaselinePath : null;
            BaselineFile? baseline = null;
            if (baselinePath is not null)
            {
                if (File.Exists(baselinePath))
                    baseline = PolicyEngine.LoadBaseline(baselinePath);
                else if (result.GetValue(BaselineFileOption) is not null)
                    throw new PolicyException($"Baseline file not found: {baselinePath}");
                else
                    Console.Error.WriteLine($"Baseline {baselinePath} (from the policy) does not exist yet; every finding counts as new. Create it with --write-baseline.");
            }
            engine = new PolicyEngine(policy, baseline);
        }
        catch (Exception ex) when (ex is PolicyException or IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Policy error: {ex.Message}");
            return ExitError;
        }

        var minSeverity = result.GetValue(MinSeverityOption);
        var showSuppressed = result.GetValue(ShowSuppressedOption);
        var reports = new List<ScanReport>();
        var format = result.GetValue(FormatOption);
        var text = new TextReporter(Console.Out, !result.GetValue(NoColorOption) && !Console.IsOutputRedirected && Environment.GetEnvironmentVariable("NO_COLOR") is null);
        Severity? max = null;
        long reportCount = 0, errorCount = 0;
        var severityCounts = new long[Enum.GetValues<Severity>().Length];
        var baselineEntries = new List<BaselineEntry>();
        var compactJson = new CliJsonContext(new JsonSerializerOptions(CliJsonContext.Default.Options) { WriteIndented = false });
        var saveDirectory = result.GetResult(SaveOption) is null ? null
            : result.GetValue(SaveOption) is { Length: > 0 } saveDir ? saveDir : ReportArchive.DefaultDirectory;
        var saved = new List<ScanReport>();
        var started = DateTimeOffset.Now;

        foreach (var report in Policed(scans, engine))
        {
            if (saveDirectory is not null)
                saved.Add(ReportArchive.Snapshot(report));
            if (writeBaseline is not null && report.Kind != "policy")
                baselineEntries.AddRange(PolicyEngine.BaselineEntries(report));
            // The exit code considers every counting finding, before the display filter.
            foreach (var finding in report.Findings.Where(f => f.Counts))
                if (max is null || finding.Severity > max)
                    max = finding.Severity;
            report.Findings.RemoveAll(f => f.Severity < minSeverity);
            report.Findings.Sort((a, b) => b.Severity.CompareTo(a.Severity));
            reportCount++;
            if (report.Error is not null) errorCount++;
            foreach (var finding in report.Findings.Where(f => f.Counts)) severityCounts[(int)finding.Severity]++;
            if (format is "json" or "sarif") reports.Add(report);
            if (format == "text")
                text.Write(report, result.GetValue(DumpTemplateOption), showSuppressed);
            else if (format == "jsonl")
                Console.WriteLine(JsonSerializer.Serialize(report, compactJson.ScanReport));
        }

        if (format == "sarif")
            Console.WriteLine(SarifWriter.Write(reports));
        else if (format == "json")
            Console.WriteLine(JsonSerializer.Serialize(reports, CliJsonContext.Default.ListScanReport));
        else if (format == "text")
            text.WriteSummary(reportCount, errorCount, severityCounts, engine.Suppressed, engine.HasBaseline ? engine.Existing : null, policy.Path);

        int code;
        if (writeBaseline is not null)
        {
            try
            {
                var file = PolicyEngine.CreateBaseline(baselineEntries);
                PolicyEngine.SaveBaseline(file, writeBaseline);
                Console.Error.WriteLine($"Wrote a baseline of {file.Entries.Count} finding(s) to {writeBaseline}.");
                code = errorCount > 0 ? ExitError : ExitClean;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"Could not write the baseline: {ex.Message}");
                code = ExitError;
            }
        }
        else
            code = ExitCode(errorCount, max, policy.FailOn);

        return saveDirectory is null ? code : SaveRun(result, saveDirectory, started, code, saved);
    }

    static int SaveRun(ParseResult result, string directory, DateTimeOffset started, int code, List<ScanReport> reports)
    {
        var command = string.Join('-', result.CommandResult.Command.Name.Split(' '));
        var run = new SavedRun(1, command, result.Tokens.Select(t => t.Value).ToList(), started, DateTimeOffset.Now, code, reports, ReportArchive.CurrentVersion);
        try
        {
            Console.Error.WriteLine($"Saved this run to {ReportArchive.Save(run, directory)}.");
            return code;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Unattended runs rely on the saved file, so a failed save must not look like success.
            Console.Error.WriteLine($"Could not save the run: {ex.Message}");
            return ExitError;
        }
    }

    /// <summary>3 on scan errors; 2 when a counting finding reaches the policy's fail-on; 1 for other Low+ findings; else 0.</summary>
    public static int ExitCode(long errorCount, Severity? max, Severity? failOn)
    {
        if (errorCount > 0) return ExitError;
        if (max is null) return ExitClean;
        if (failOn is not null && max >= failOn) return ExitHighRisk;
        return max >= Severity.Low ? ExitWarnings : ExitClean;
    }

    static IEnumerable<ScanReport> Policed(IEnumerable<ScanReport> scans, PolicyEngine engine)
    {
        foreach (var report in scans)
        {
            engine.Apply(report);
            yield return report;
        }
        if (engine.Finish() is { } policyReport)
            yield return policyReport;
    }
}

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, UseStringEnumConverter = true)]
[JsonSerializable(typeof(List<ScanReport>))]
internal sealed partial class CliJsonContext : JsonSerializerContext;
