using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Rules.Policy;

/// <summary>A suppression: findings of <see cref="Rule"/> on matching targets are kept but no longer count, until <see cref="Expires"/>.</summary>
public sealed record Suppression(int Index, string Rule, string Target, string? Location, string Reason, DateOnly Expires);

/// <summary>
/// A team's policy for modelcheck (<c>.modelcheck.yml</c> / <c>.yaml</c> / <c>.json</c>):
/// allow-listed publishers and models, suppressions that need a reason and expire, per-rule severity
/// overrides, the severity that fails a run, and an optional baseline of already-known findings.
/// </summary>
public sealed class ModelPolicy
{
    public static readonly string[] FileNames = [".modelcheck.yml", ".modelcheck.yaml", ".modelcheck.json"];

    /// <summary>Rules about who published a model or where it came from; allow-listing a publisher or model downgrades them to Info.</summary>
    public static readonly HashSet<string> ProvenanceRules = ["H006", "H007", "H008", "H011", "P001", "P002", "P003"];

    public string? Path { get; init; }
    public IReadOnlyList<string> AllowPublishers { get; init; } = [];
    public IReadOnlyList<string> AllowModels { get; init; } = [];
    public IReadOnlyList<Suppression> Suppressions { get; init; } = [];

    /// <summary>Rule id or glob → severity; null means "off" (the finding is dropped).</summary>
    public IReadOnlyDictionary<string, Severity?> SeverityOverrides { get; init; } = new Dictionary<string, Severity?>();

    /// <summary>Counting findings at or above this fail the run (exit 2). Null means "never".</summary>
    public Severity? FailOn { get; init; } = Severity.High;

    /// <summary>Baseline file, resolved relative to the policy file.</summary>
    public string? BaselinePath { get; init; }

    public static ModelPolicy Default { get; } = new();

    /// <summary>Finds a policy file in <paramref name="directory"/> or its parents.</summary>
    public static string? Discover(string directory)
    {
        for (var dir = new DirectoryInfo(directory); dir is not null; dir = dir.Parent)
            foreach (var name in FileNames)
            {
                var candidate = System.IO.Path.Combine(dir.FullName, name);
                if (File.Exists(candidate)) return candidate;
            }
        return null;
    }

    public static ModelPolicy Load(string path)
    {
        var text = File.ReadAllText(path);
        object? tree;
        if (path.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
                tree = MiniYaml.FromJson(doc.RootElement);
            }
            catch (JsonException ex)
            {
                throw new PolicyException($"Invalid JSON: {ex.Message}");
            }
        }
        else
            tree = MiniYaml.Parse(text);
        return Bind(tree, path);
    }

    static readonly HashSet<string> TopLevelKeys = ["version", "fail-on", "allow", "severity", "suppress", "baseline"];

    public static ModelPolicy Bind(object? tree, string? path)
    {
        if (tree is null)
            return new ModelPolicy { Path = path };
        if (tree is not Dictionary<string, object?> root)
            throw new PolicyException("The policy must be a mapping of keys (version, fail-on, allow, severity, suppress, baseline).");

        foreach (var key in root.Keys.Where(k => !TopLevelKeys.Contains(k)))
            throw new PolicyException($"Unknown key '{key}'. Allowed: {string.Join(", ", TopLevelKeys)}.");
        if (root.TryGetValue("version", out var version) && version is not ("1" or null))
            throw new PolicyException($"Unsupported policy version '{version}'; this modelcheck understands version 1.");

        var allow = root.GetValueOrDefault("allow") switch
        {
            null => [],
            Dictionary<string, object?> a => a,
            _ => throw new PolicyException("'allow' must be a mapping with 'publishers' and/or 'models'."),
        };
        foreach (var key in allow.Keys.Where(k => k is not ("publishers" or "models")))
            throw new PolicyException($"Unknown key 'allow.{key}'. Allowed: publishers, models.");

        var directory = path is null ? Environment.CurrentDirectory : System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!;
        var baseline = root.GetValueOrDefault("baseline") switch
        {
            null => null,
            string b when b.Length > 0 => System.IO.Path.GetFullPath(System.IO.Path.Combine(directory, b)),
            _ => throw new PolicyException("'baseline' must be a file path."),
        };

        return new ModelPolicy
        {
            Path = path,
            AllowPublishers = StringList(allow.GetValueOrDefault("publishers"), "allow.publishers"),
            AllowModels = StringList(allow.GetValueOrDefault("models"), "allow.models"),
            SeverityOverrides = Overrides(root.GetValueOrDefault("severity")),
            Suppressions = ParseSuppressions(root.GetValueOrDefault("suppress")),
            FailOn = root.GetValueOrDefault("fail-on") switch
            {
                null => Severity.High,
                string s when s.Equals("never", StringComparison.OrdinalIgnoreCase) => null,
                string s => ParseSeverity(s, "fail-on") ?? throw new PolicyException("'fail-on' cannot be 'off'; use 'never'."),
                _ => throw new PolicyException("'fail-on' must be info, low, medium, high, critical or never."),
            },
            BaselinePath = baseline,
        };
    }

    static List<string> StringList(object? node, string key) => node switch
    {
        null => [],
        string s => [s],
        List<object?> list => list.Select((v, i) => v as string ?? throw new PolicyException($"'{key}[{i}]' must be a string.")).ToList(),
        _ => throw new PolicyException($"'{key}' must be a list of strings."),
    };

    static Dictionary<string, Severity?> Overrides(object? node)
    {
        if (node is null) return [];
        if (node is not Dictionary<string, object?> map)
            throw new PolicyException("'severity' must map rule ids to a severity or 'off', e.g. 'T009: off'.");
        var result = new Dictionary<string, Severity?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (rule, value) in map)
        {
            CheckRulePattern(rule, $"severity.{rule}");
            result[rule] = value is string s ? ParseSeverity(s, $"severity.{rule}") : throw new PolicyException($"'severity.{rule}' must be a severity or 'off'.");
        }
        return result;
    }

    static List<Suppression> ParseSuppressions(object? node)
    {
        if (node is null) return [];
        if (node is not List<object?> list)
            throw new PolicyException("'suppress' must be a list of entries with rule, reason and expires.");
        var result = new List<Suppression>();
        for (var i = 0; i < list.Count; i++)
        {
            var where = $"suppress[{i}]";
            if (list[i] is not Dictionary<string, object?> entry)
                throw new PolicyException($"'{where}' must be a mapping with rule, reason and expires.");
            foreach (var key in entry.Keys.Where(k => k is not ("rule" or "target" or "location" or "reason" or "expires")))
                throw new PolicyException($"Unknown key '{where}.{key}'. Allowed: rule, target, location, reason, expires.");

            var rule = entry.GetValueOrDefault("rule") as string ?? throw new PolicyException($"'{where}.rule' is required (a rule id such as H007, or a glob such as T00*).");
            CheckRulePattern(rule, $"{where}.rule");
            var reason = (entry.GetValueOrDefault("reason") as string)?.Trim();
            if (string.IsNullOrEmpty(reason))
                throw new PolicyException($"'{where}.reason' is required: say why this finding is acceptable.");
            var expiresText = entry.GetValueOrDefault("expires") as string
                ?? throw new PolicyException($"'{where}.expires' is required (yyyy-MM-dd), so suppressions are revisited.");
            if (!DateOnly.TryParseExact(expiresText, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var expires))
                throw new PolicyException($"'{where}.expires' must be a date like 2027-03-31, not '{expiresText}'.");
            result.Add(new Suppression(i, rule, entry.GetValueOrDefault("target") as string ?? "**", entry.GetValueOrDefault("location") as string, reason, expires));
        }
        return result;
    }

    static void CheckRulePattern(string rule, string where)
    {
        if (!Regex.IsMatch(rule, @"^[A-Za-z0-9*?]+$"))
            throw new PolicyException($"'{where}': '{rule}' is not a rule id or glob (e.g. H007, T00*, *).");
    }

    static Severity? ParseSeverity(string value, string where) =>
        value.Equals("off", StringComparison.OrdinalIgnoreCase) ? null
        : Enum.TryParse<Severity>(value, ignoreCase: true, out var s) && Enum.IsDefined(s) && !char.IsDigit(value[0]) ? s
        : throw new PolicyException($"'{where}': '{value}' is not a severity (info, low, medium, high, critical) or 'off'.");

    /// <summary>Glob match: <c>**</c> crosses '/', <c>*</c> does not, <c>?</c> is one character. Case-insensitive; '\' is treated as '/'.</summary>
    public static bool Glob(string pattern, string value)
    {
        var regex = "^" + Regex.Escape(pattern.Replace('\\', '/'))
            .Replace(@"\*\*", "\u0001").Replace(@"\*", "[^/]*").Replace(@"\?", "[^/]").Replace("\u0001", ".*") + "$";
        return Regex.IsMatch(value.Replace('\\', '/'), regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }
}
