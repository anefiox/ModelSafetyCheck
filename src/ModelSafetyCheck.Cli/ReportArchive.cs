using System.Text.Json;
using System.Text.Json.Serialization;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Cli;

/// <summary>One saved run: what was run, when, its exit code and every report with all findings.</summary>
public sealed record SavedRun(
    int Version,
    string Command,
    IReadOnlyList<string> Arguments,
    DateTimeOffset Started,
    DateTimeOffset Finished,
    int ExitCode,
    List<ScanReport> Reports,
    string? ScannerVersion = null);

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, UseStringEnumConverter = true)]
[JsonSerializable(typeof(SavedRun))]
internal sealed partial class ArchiveJsonContext : JsonSerializerContext;

/// <summary>
/// The `--save` option: keeps a timestamped JSON copy of each run, so findings can be compared over time. The copy holds
/// every finding, before --min-severity hides any, with suppressed and baselined ones marked as such.
/// </summary>
public static class ReportArchive
{
    public static string CurrentVersion => typeof(ReportArchive).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    public static string DefaultDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".modelcheck", "reports");

    /// <summary>A copy whose finding list is not affected by the display filter applied to the original.</summary>
    public static ScanReport Snapshot(ScanReport report) => new()
    {
        Target = report.Target,
        Kind = report.Kind,
        Path = report.Path,
        Fingerprint = report.Fingerprint,
        ContentHashes = report.ContentHashes,
        Summary = report.Summary,
        Findings = [.. report.Findings],
        Templates = report.Templates,
        Error = report.Error,
    };

    /// <summary>Writes the run to <paramref name="directory"/> as yyyyMMdd-HHmmss-command.json (UTC) and returns the path.</summary>
    public static string Save(SavedRun run, string directory)
    {
        Directory.CreateDirectory(directory);
        var stem = $"{run.Started.UtcDateTime:yyyyMMdd-HHmmss}-{run.Command}";
        var json = JsonSerializer.Serialize(run, ArchiveJsonContext.Default.SavedRun) + "\n";
        for (var n = 1; ; n++)
        {
            var path = Path.Combine(directory, n == 1 ? $"{stem}.json" : $"{stem}-{n}.json");
            try
            {
                // CreateNew: two runs in the same second (e.g. batch jobs) must not overwrite each other.
                using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write);
                using var writer = new StreamWriter(stream);
                writer.Write(json);
                return Path.GetFullPath(path);
            }
            catch (IOException) when (File.Exists(path) && n < 1000)
            {
            }
        }
    }

    public static SavedRun? Load(string path) =>
        JsonSerializer.Deserialize(File.ReadAllText(path), ArchiveJsonContext.Default.SavedRun);
}
