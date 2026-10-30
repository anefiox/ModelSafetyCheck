using System.CommandLine;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Cli;

/// <summary>One scanned target in an exported dataset: its latest scan.</summary>
public sealed record ExportTarget(
    string Target, string? Repo, string? File, string Kind, string ScannedAt, string Command, string? ScannerVersion,
    string? MaxSeverity, int Findings, int Critical, int High, int Medium, int Low, int Info, string? Error,
    string? Architecture, long? FileSize, int? TensorCount, string? Sha256, string? Source);

/// <summary>One finding in an exported dataset.</summary>
public sealed record ExportFinding(
    string Target, string? Repo, string? File, string ScannedAt, string RuleId, string Severity, string Title,
    string? Location, string Detail, bool Counts);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ExportTarget))]
[JsonSerializable(typeof(ExportFinding))]
internal sealed partial class ExportJsonContext : JsonSerializerContext;

/// <summary>
/// `modelcheck export`: turns runs saved with --save into a dataset that can be queried (CSV and JSON Lines, readable by
/// DuckDB, SQLite, pandas or a spreadsheet) and published: targets, findings and a README summary. Only the latest scan
/// of each target is kept. By default only remote scans (repo, batch, lineage) are exported, so no local paths or
/// machine details leave the computer; local file paths are never written.
/// </summary>
public static class ExportCommand
{
    static readonly string[] RemoteCommands = ["repo", "batch", "lineage"];

    public static Command Create()
    {
        var reports = new Option<string>("--reports") { Description = "Directory of saved runs.", DefaultValueFactory = _ => ReportArchive.DefaultDirectory };
        var output = new Option<string>("--out", "-o") { Description = "Directory to write the dataset to.", Required = true };
        var batchDir = new Option<string[]>("--batch-dir") { Description = "Batch directories (batch --directory) whose download receipts add each file's sha256 and pinned source URL. Repeatable." };
        var includeLocal = new Option<bool>("--include-local") { Description = "Also export scans of this machine (scan, local, audit, watch). They contain local paths: do not publish them." };
        var command = new Command("export", "Export runs saved with --save as a queryable dataset (targets and findings as CSV and JSON Lines, plus a README summary).")
        {
            reports, output, batchDir, includeLocal,
        };
        command.SetAction(result => Run(result.GetValue(reports)!, result.GetValue(output)!, result.GetValue(includeLocal), Console.Out,
            result.GetValue(batchDir) ?? []));
        return command;
    }

    public static int Run(string reportsDirectory, string outputDirectory, bool includeLocal, TextWriter log, IReadOnlyList<string>? batchDirectories = null)
    {
        var receipts = Receipts(batchDirectories ?? []);
        if (!Directory.Exists(reportsDirectory))
        {
            Console.Error.WriteLine($"No saved runs in {reportsDirectory}. Add --save to a scan first.");
            return Program.ExitError;
        }

        // Latest scan of every target, across all saved runs.
        var latest = new Dictionary<string, (SavedRun Run, ScanReport Report)>(StringComparer.Ordinal);
        int runs = 0, skipped = 0;
        foreach (var file in Directory.GetFiles(reportsDirectory, "*.json").Order(StringComparer.Ordinal))
        {
            SavedRun? run;
            try
            {
                run = ReportArchive.Load(file);
            }
            catch (Exception ex) when (ex is JsonException or IOException)
            {
                Console.Error.WriteLine($"Skipping {Path.GetFileName(file)}: {ex.Message}");
                continue;
            }
            if (run is null) continue;
            if (!includeLocal && !RemoteCommands.Contains(run.Command))
            {
                skipped++;
                continue;
            }
            runs++;
            foreach (var report in run.Reports.Where(r => r.Kind != "policy" && r.Target != "hf:discover"))
                if (!latest.TryGetValue(report.Target, out var seen) || seen.Run.Started <= run.Started)
                    latest[report.Target] = (run, report);
        }

        var targets = new List<ExportTarget>();
        var findings = new List<ExportFinding>();
        foreach (var (run, report) in latest.Values.OrderBy(v => v.Report.Target, StringComparer.Ordinal))
        {
            var (repo, file) = SplitTarget(report.Target);
            var scannedAt = run.Started.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
            var counting = report.Findings.Where(f => f.Counts).ToList();
            int Count(Severity s) => counting.Count(f => f.Severity == s);
            targets.Add(new ExportTarget(report.Target, repo, file, report.Kind, scannedAt, run.Command, run.ScannerVersion,
                counting.Count == 0 ? null : Name(counting.Max(f => f.Severity)), counting.Count,
                Count(Severity.Critical), Count(Severity.High), Count(Severity.Medium), Count(Severity.Low), Count(Severity.Info),
                report.Error, report.Summary?.Architecture, report.Summary?.FileSize, report.Summary?.TensorCount,
                receipts.GetValueOrDefault(Key(report.Target)).Sha256, receipts.GetValueOrDefault(Key(report.Target)).Source));
            findings.AddRange(report.Findings
                .OrderByDescending(f => f.Severity).ThenBy(f => f.RuleId, StringComparer.Ordinal)
                .Select(f => new ExportFinding(report.Target, repo, file, scannedAt, f.RuleId, Name(f.Severity), f.Title,
                    includeLocal ? f.Location : Scrub(f.Location), f.Detail, f.Counts)));
        }

        Directory.CreateDirectory(outputDirectory);
        WriteJsonLines(Path.Combine(outputDirectory, "targets.jsonl"), targets, ExportJsonContext.Default.ExportTarget);
        WriteJsonLines(Path.Combine(outputDirectory, "findings.jsonl"), findings, ExportJsonContext.Default.ExportFinding);
        WriteCsv(Path.Combine(outputDirectory, "targets.csv"),
            ["target", "repo", "file", "kind", "scanned_at", "command", "scanner_version", "max_severity", "findings", "critical", "high", "medium", "low", "info", "error", "architecture", "file_size", "tensor_count", "sha256", "source"],
            targets.Select(t => new object?[] { t.Target, t.Repo, t.File, t.Kind, t.ScannedAt, t.Command, t.ScannerVersion, t.MaxSeverity, t.Findings, t.Critical, t.High, t.Medium, t.Low, t.Info, t.Error, t.Architecture, t.FileSize, t.TensorCount, t.Sha256, t.Source }));
        WriteCsv(Path.Combine(outputDirectory, "findings.csv"),
            ["target", "repo", "file", "scanned_at", "rule_id", "severity", "title", "location", "detail", "counts"],
            findings.Select(f => new object?[] { f.Target, f.Repo, f.File, f.ScannedAt, f.RuleId, f.Severity, f.Title, f.Location, f.Detail, f.Counts }));
        File.WriteAllText(Path.Combine(outputDirectory, "README.md"), Summary(targets, findings));

        log.WriteLine($"Exported {targets.Count} target(s) and {findings.Count} finding(s) from {runs} run(s) to {Path.GetFullPath(outputDirectory)}.");
        if (skipped > 0)
            log.WriteLine($"Left out {skipped} run(s) of this machine (scan, local, audit, watch); --include-local adds them.");
        return Program.ExitClean;
    }

    static string Name(Severity s) => s.ToString().ToLowerInvariant();

    /// <summary>"hf:org/name/dir/file.gguf" → ("org/name", "dir/file.gguf"); "org/name" → ("org/name", null).</summary>
    public static (string? Repo, string? File) SplitTarget(string target)
    {
        var id = target.StartsWith("hf:", StringComparison.Ordinal) ? target[3..] : target;
        if (id.Contains("://", StringComparison.Ordinal) || id.StartsWith("ollama:", StringComparison.Ordinal))
            return (null, null);
        var parts = id.Split('/', 3);
        return parts.Length switch
        {
            >= 3 => ($"{parts[0]}/{parts[1]}", parts[2]),
            2 => (id, null),
            _ => (null, null),
        };
    }

    static string Key(string target) => target.StartsWith("hf:", StringComparison.Ordinal) ? target[3..] : target;

    /// <summary>Download receipts from batch results/*.json, keyed like batch targets: "&lt;model id&gt;/&lt;file path&gt;".</summary>
    static Dictionary<string, (string? Sha256, string? Source)> Receipts(IEnumerable<string> batchDirectories)
    {
        var receipts = new Dictionary<string, (string?, string?)>(StringComparer.Ordinal);
        foreach (var directory in batchDirectories)
        {
            var results = Path.Combine(directory, "results");
            if (!Directory.Exists(results))
            {
                Console.Error.WriteLine($"No batch results in {directory}.");
                continue;
            }
            foreach (var file in Directory.GetFiles(results, "*.json"))
            {
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(file));
                    if (!doc.RootElement.TryGetProperty("id", out var id) || !doc.RootElement.TryGetProperty("files", out var files) ||
                        files.ValueKind != JsonValueKind.Array)
                        continue;
                    foreach (var f in files.EnumerateArray())
                    {
                        string? Str(string name) => f.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
                        if (Str("path") is { } path)
                            receipts[$"{id.GetString()}/{path}"] = (Str("sha256"), Str("source"));
                    }
                }
                catch (Exception ex) when (ex is JsonException or IOException) { }
            }
        }
        return receipts;
    }

    /// <summary>Removes absolute local paths (a batch download directory) from a location.</summary>
    static string? Scrub(string? location) =>
        location is not null && (Path.IsPathFullyQualified(location) || location.StartsWith('/')) ? Path.GetFileName(location) : location;

    static void WriteJsonLines<T>(string path, IEnumerable<T> rows, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type)
    {
        using var writer = new StreamWriter(path, false, new UTF8Encoding(false));
        foreach (var row in rows)
            writer.WriteLine(JsonSerializer.Serialize(row, type));
    }

    static void WriteCsv(string path, string[] header, IEnumerable<object?[]> rows)
    {
        using var writer = new StreamWriter(path, false, new UTF8Encoding(false));
        writer.WriteLine(string.Join(',', header));
        foreach (var row in rows)
            writer.WriteLine(string.Join(',', row.Select(Csv)));
    }

    static string Csv(object? value)
    {
        var text = value switch
        {
            null => "",
            bool b => b ? "true" : "false",
            IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
            _ => value.ToString() ?? "",
        };
        // Quote anything a spreadsheet could misread; a leading =, +, - or @ would otherwise run as a formula.
        if (text.Length > 0 && "=+-@".Contains(text[0]))
            text = "'" + text;
        return text.IndexOfAny([',', '"', '\n', '\r']) >= 0 || text.StartsWith('\'') ? $"\"{text.Replace("\"", "\"\"")}\"" : text;
    }

    static string Summary(List<ExportTarget> targets, List<ExportFinding> findings)
    {
        var counting = findings.Where(f => f.Counts).ToList();
        var repos = targets.Select(t => t.Repo).Where(r => r is not null).Distinct().Count();
        var files = targets.Count(t => t.File is not null);
        var dates = targets.Select(t => t.ScannedAt[..10]).Order().ToList();
        var versions = targets.Select(t => t.ScannerVersion ?? "unknown").Distinct().Order();
        var sb = new StringBuilder();
        sb.AppendLine("# modelcheck scan results").AppendLine();
        sb.AppendLine($"Scanned {repos} Hugging Face repo(s) and {files} model file(s)" +
                      (dates.Count > 0 ? $" between {dates[0]} and {dates[^1]}" : "") + $" with modelcheck {string.Join(", ", versions)}.").AppendLine();
        sb.AppendLine("Only the latest scan of each target is included. A finding marks something to review, not proof of malice; ")
          .AppendLine("a clean result cannot prove weights are free of trained-in backdoors. See the rule reference in docs/rules.md.").AppendLine();

        sb.AppendLine("## Findings by severity").AppendLine().AppendLine("| Severity | Findings | Targets |").AppendLine("|---|---:|---:|");
        foreach (var s in Enum.GetValues<Severity>().Reverse())
        {
            var rows = counting.Where(f => f.Severity == Name(s)).ToList();
            sb.AppendLine($"| {Name(s)} | {rows.Count} | {rows.Select(f => f.Target).Distinct().Count()} |");
        }
        var errors = targets.Count(t => t.Error is not null);
        if (errors > 0)
            sb.AppendLine().AppendLine($"{errors} target(s) could not be scanned (see the `error` column of targets.csv).");

        sb.AppendLine().AppendLine("## Findings by rule").AppendLine().AppendLine("| Rule | Severity | Title | Findings | Repos |").AppendLine("|---|---|---|---:|---:|");
        foreach (var g in counting.Where(f => f.Severity != "info").GroupBy(f => (f.RuleId, f.Severity))
                     .OrderByDescending(g => Enum.Parse<Severity>(g.Key.Severity, true)).ThenByDescending(g => g.Count()))
            sb.AppendLine($"| {g.Key.RuleId} | {g.Key.Severity} | {Md(g.First().Title)} | {g.Count()} | {g.Select(f => f.Repo).Distinct().Count()} |");

        var notable = counting.Where(f => f.Severity is "critical" or "high" or "medium")
            .GroupBy(f => (f.Repo ?? f.Target, f.RuleId)).Select(g => g.First())
            .OrderByDescending(f => Enum.Parse<Severity>(f.Severity, true)).ThenBy(f => f.Repo).ToList();
        if (notable.Count > 0)
        {
            sb.AppendLine().AppendLine("## Medium and above, one row per repo and rule").AppendLine()
              .AppendLine("| Repo | Rule | Severity | Detail |").AppendLine("|---|---|---|---|");
            foreach (var f in notable)
                sb.AppendLine($"| {Md(f.Repo ?? f.Target)} | {f.RuleId} | {f.Severity} | {Md(TextHeuristics.Truncate(f.Detail, 220))} |");
        }

        sb.AppendLine().AppendLine("## Files").AppendLine().AppendLine("""
            - `targets.csv` / `targets.jsonl`: one row per scanned repo or file (latest scan), with severity counts.
            - `findings.csv` / `findings.jsonl`: one row per finding. `counts` is false for suppressed or baselined findings.

            Query with DuckDB, for example:

            ```sql
            SELECT rule_id, severity, count(*) AS findings, count(DISTINCT repo) AS repos
            FROM 'findings.csv' WHERE counts AND severity <> 'info'
            GROUP BY ALL ORDER BY findings DESC;
            ```

            Regenerate with `modelcheck export --out <dir>` after scanning with `--save`.
            """);
        return sb.ToString();
    }

    static string Md(string text) => text.Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ");
}
