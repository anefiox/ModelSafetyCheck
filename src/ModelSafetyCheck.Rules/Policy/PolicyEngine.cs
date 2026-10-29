using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Rules.Policy;

public sealed record BaselineEntry(string Fingerprint, string RuleId, string Target, string Title);

public sealed record BaselineFile(int Version, string Created, IReadOnlyList<BaselineEntry> Entries);

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(BaselineFile))]
public sealed partial class PolicyJsonContext : JsonSerializerContext;

/// <summary>
/// Applies a <see cref="ModelPolicy"/> to scan reports, in this order: severity overrides (including "off"),
/// allow-lists (provenance findings for allowed publishers/models become Info), suppressions (kept but marked,
/// so they no longer count), then the baseline (findings already in it are marked "existing").
/// </summary>
public sealed partial class PolicyEngine
{
    readonly ModelPolicy _policy;
    readonly HashSet<string>? _baseline;
    readonly DateOnly _today;
    readonly int[] _activeUses;
    readonly int[] _expiredUses;

    public int Suppressed { get; private set; }
    public int Existing { get; private set; }
    public int Dropped { get; private set; }
    public bool HasBaseline => _baseline is not null;

    public PolicyEngine(ModelPolicy policy, BaselineFile? baseline = null, DateOnly? today = null)
    {
        _policy = policy;
        _baseline = baseline?.Entries.Select(e => e.Fingerprint).ToHashSet(StringComparer.Ordinal);
        _today = today ?? DateOnly.FromDateTime(DateTime.UtcNow);
        _activeUses = new int[policy.Suppressions.Count];
        _expiredUses = new int[policy.Suppressions.Count];
    }

    public void Apply(ScanReport report)
    {
        var publisher = PublisherOf(report.Target);
        var allowed = _policy.AllowModels.Any(g => ModelPolicy.Glob(g, report.Target) || (report.Path is not null && ModelPolicy.Glob(g, report.Path)))
                      || (publisher is not null && _policy.AllowPublishers.Any(p => ModelPolicy.Glob(p, publisher)));

        var result = new List<Finding>(report.Findings.Count);
        foreach (var original in report.Findings)
        {
            var f = original;
            if (Override(f.RuleId) is (true, var over))
            {
                if (over is null) { Dropped++; continue; }
                f = f with { Severity = over.Value };
            }

            if (allowed && ModelPolicy.ProvenanceRules.Contains(f.RuleId) && f.Severity > Severity.Info)
                f = f with { Severity = Severity.Info, Detail = f.Detail + $"\nDowngraded to Info: allowed by the policy ({(publisher is not null && _policy.AllowPublishers.Any(p => ModelPolicy.Glob(p, publisher)) ? $"publisher {publisher}" : "allowed model")})." };

            var match = _policy.Suppressions.Where(s => Matches(s, report, f)).ToList();
            var active = match.FirstOrDefault(s => s.Expires >= _today);
            foreach (var expired in match.Where(s => s.Expires < _today))
                _expiredUses[expired.Index]++;
            if (active is not null)
            {
                _activeUses[active.Index]++;
                Suppressed++;
                f = f with { Suppression = $"{active.Reason} (policy suppress[{active.Index}], until {active.Expires.Invariant()})" };
            }
            else if (_baseline is not null)
            {
                var existing = _baseline.Contains(Fingerprint(report.Target, f));
                if (existing) Existing++;
                f = f with { Baseline = existing ? "existing" : "new" };
            }
            result.Add(f);
        }
        report.Findings.Clear();
        report.Findings.AddRange(result);
    }

    /// <summary>
    /// After all reports: one report about the policy itself. Expired suppressions are Low (they stopped applying and
    /// need a decision); suppressions that matched nothing are Info (stale entries to clean up). Null when there is nothing to say.
    /// </summary>
    public ScanReport? Finish()
    {
        var report = new ScanReport { Target = _policy.Path is null ? "policy" : $"policy:{_policy.Path}", Kind = "policy" };
        foreach (var s in _policy.Suppressions)
        {
            if (s.Expires < _today)
                report.Findings.Add(new Finding("PL001", Severity.Low, $"Suppression for {s.Rule} expired on {s.Expires.Invariant()}",
                    $"suppress[{s.Index}] (\"{s.Reason}\") no longer applies{(_expiredUses[s.Index] > 0 ? $"; {_expiredUses[s.Index]} finding(s) count again" : "")}. " +
                    "Fix the findings, or renew the suppression with a new expiry date if the reason still holds.", $"suppress[{s.Index}]"));
            else if (_activeUses[s.Index] == 0)
                report.Findings.Add(new Finding("PL002", Severity.Info, $"Suppression for {s.Rule} matched no finding",
                    $"suppress[{s.Index}] (\"{s.Reason}\") did not match anything in this run. Remove it if the finding is gone for good.", $"suppress[{s.Index}]"));
        }
        return report.Findings.Count > 0 ? report : null;
    }

    /// <summary>The override for a rule: (true, severity), (true, null) for "off", or (false, _) when none applies.</summary>
    (bool Found, Severity? Severity) Override(string ruleId)
    {
        if (_policy.SeverityOverrides.TryGetValue(ruleId, out var exact)) return (true, exact);
        foreach (var (pattern, severity) in _policy.SeverityOverrides)
            if (ModelPolicy.Glob(pattern, ruleId)) return (true, severity);
        return (false, null);
    }

    static bool Matches(Suppression s, ScanReport report, Finding f) =>
        ModelPolicy.Glob(s.Rule, f.RuleId)
        && (ModelPolicy.Glob(s.Target, report.Target) || (report.Path is not null && ModelPolicy.Glob(s.Target, report.Path)))
        && (s.Location is null || (f.Location is not null && ModelPolicy.Glob(s.Location, f.Location)));

    [GeneratedRegex(@"\d+")]
    private static partial Regex DigitsRegex();

    /// <summary>
    /// Stable identity of a finding across runs and machines: rule, target (relative to the current directory when
    /// inside it, '/' separators), location and title with numbers masked, so counts and versions do not break a match.
    /// </summary>
    public static string Fingerprint(string target, Finding f)
    {
        var key = $"{f.RuleId}|{NormalizeTarget(target)}|{f.Location ?? ""}|{DigitsRegex().Replace(f.Title, "#")}";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..32];
    }

    static string NormalizeTarget(string target)
    {
        if (Path.IsPathFullyQualified(target))
        {
            var relative = Path.GetRelativePath(Environment.CurrentDirectory, target);
            if (!relative.StartsWith("..", StringComparison.Ordinal) && !Path.IsPathFullyQualified(relative))
                target = relative;
        }
        return target.Replace('\\', '/');
    }

    /// <summary>The publisher a target belongs to: the Hugging Face org, the Ollama namespace ("library" for official models).</summary>
    public static string? PublisherOf(string target)
    {
        var t = target.Replace('\\', '/');
        string? rest = null;
        foreach (var prefix in new[] { "hf:", "lmstudio:", "ollama:hf.co/", "ollama:huggingface.co/" })
            if (t.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) { rest = t[prefix.Length..]; break; }
        if (rest is not null)
            return rest.Contains('/') ? rest[..rest.IndexOf('/')] : null;
        if (t.StartsWith("hf-cache:models--", StringComparison.OrdinalIgnoreCase))
        {
            var name = t["hf-cache:models--".Length..].Split('/')[0];
            var sep = name.IndexOf("--", StringComparison.Ordinal);
            return sep > 0 ? name[..sep] : null;
        }
        if (t.StartsWith("ollama:", StringComparison.OrdinalIgnoreCase))
        {
            var model = t["ollama:".Length..].Split(' ')[0];
            return model.Contains('/') ? model[..model.IndexOf('/')] : "library";
        }
        return null;
    }

    /// <summary>Baseline entries for a report's findings, skipping suppressed ones (the suppression already covers them).</summary>
    public static IEnumerable<BaselineEntry> BaselineEntries(ScanReport report) =>
        report.Findings.Where(f => f.Suppression is null)
            .Select(f => new BaselineEntry(Fingerprint(report.Target, f), f.RuleId, NormalizeTarget(report.Target), f.Title));

    public static BaselineFile CreateBaseline(IEnumerable<BaselineEntry> entries) =>
        new(1, DateTimeOffset.UtcNow.ToString("O"), entries
            .DistinctBy(e => e.Fingerprint)
            .OrderBy(e => e.Target, StringComparer.Ordinal).ThenBy(e => e.RuleId, StringComparer.Ordinal)
            .ToList());

    public static void SaveBaseline(BaselineFile baseline, string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (dir is not null) Directory.CreateDirectory(dir);
        File.WriteAllText(path, JsonSerializer.Serialize(baseline, PolicyJsonContext.Default.BaselineFile) + "\n");
    }

    public static BaselineFile LoadBaseline(string path)
    {
        try
        {
            return JsonSerializer.Deserialize(File.ReadAllText(path), PolicyJsonContext.Default.BaselineFile)
                   ?? throw new PolicyException($"Baseline {path} is empty.");
        }
        catch (JsonException ex)
        {
            throw new PolicyException($"Baseline {path} is not a valid baseline file: {ex.Message}");
        }
    }
}
