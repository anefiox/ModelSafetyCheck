using System.Text.Json;
using System.Text.Json.Serialization;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Local;

public sealed record ModelSnapshot(string Target, string Kind, string? Fingerprint, Dictionary<string, string> ContentHashes);

public sealed record SnapshotFile(int Version, DateTimeOffset Captured, List<ModelSnapshot> Models);

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(SnapshotFile))]
public sealed partial class WatchJsonContext : JsonSerializerContext;

/// <summary>
/// The `watch` command: remembers the hash of every template and system prompt the local runners use,
/// and reports changes. A template that changes while the model weights stay the same is what a
/// drive-by rewrite through the runner's API looks like (DNS rebinding, exposed port).
/// </summary>
public static class TemplateWatch
{
    public static string DefaultStorePath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".modelcheck", "snapshots.json");

    public static SnapshotFile Capture(IEnumerable<ScanReport> reports) =>
        new(1, DateTimeOffset.UtcNow, reports
            .Where(r => r.Error is null)
            .Select(r => new ModelSnapshot(r.Target, r.Kind, r.Fingerprint, new Dictionary<string, string>(r.ContentHashes)))
            .ToList());

    public static void Save(SnapshotFile snapshot, string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        File.WriteAllText(path, JsonSerializer.Serialize(snapshot, WatchJsonContext.Default.SnapshotFile));
    }

    public static SnapshotFile? Load(string path)
    {
        if (!File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize(File.ReadAllText(path), WatchJsonContext.Default.SnapshotFile);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static ScanReport Compare(SnapshotFile baseline, SnapshotFile current)
    {
        var report = new ScanReport { Target = $"template drift since {baseline.Captured:yyyy-MM-dd HH:mm} UTC", Kind = "watch" };
        var before = baseline.Models.GroupBy(m => m.Target).ToDictionary(g => g.Key, g => g.First());
        var after = current.Models.GroupBy(m => m.Target).ToDictionary(g => g.Key, g => g.First());

        foreach (var (target, now) in after)
        {
            if (!before.TryGetValue(target, out var then))
            {
                report.Findings.Add(new Finding("W003", Severity.Info, "New model since the baseline", $"{target} was added.", target));
                continue;
            }

            var changed = now.ContentHashes.Keys.Union(then.ContentHashes.Keys)
                .Where(location => now.ContentHashes.GetValueOrDefault(location) != then.ContentHashes.GetValueOrDefault(location))
                .Select(location => Describe(location, then.ContentHashes.GetValueOrDefault(location), now.ContentHashes.GetValueOrDefault(location)))
                .ToList();
            if (changed.Count == 0)
                continue;

            if (now.Fingerprint is null && then.Fingerprint is null)
                report.Findings.Add(new Finding("W001", Severity.Medium, "Template or system prompt override changed",
                    $"{target}: {string.Join("; ", changed)}. Fine if you edited it yourself; otherwise something rewrote the runner's settings.", target));
            else if (now.Fingerprint == then.Fingerprint)
                report.Findings.Add(new Finding("W001", Severity.High, "Template or system prompt changed without a model update",
                    $"{target}: the weights are unchanged but {string.Join("; ", changed)}. Rewriting a template through the runner's API (for example from a web page via DNS rebinding, " +
                    "or over an exposed port) leaves exactly this trace. Inspect it with `modelcheck local --dump-template`, then re-pull the model if you did not make this change.",
                    target));
            else
                report.Findings.Add(new Finding("W002", Severity.Info, "Model updated, with a different template",
                    $"{target}: the weights changed and {string.Join("; ", changed)}. Usually a normal update; its new template was scanned above.", target));
        }

        foreach (var target in before.Keys.Except(after.Keys))
            report.Findings.Add(new Finding("W003", Severity.Info, "Model removed since the baseline", $"{target} is gone.", target));
        return report;
    }

    static string Describe(string location, string? then, string? now) => (then, now) switch
    {
        (null, _) => $"{location} was added",
        (_, null) => $"{location} was removed",
        _ => $"{location} changed ({then[..12]} -> {now[..12]})",
    };
}
