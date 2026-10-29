using System.Text.Json.Serialization;

namespace ModelSafetyCheck.Core;

[JsonConverter(typeof(JsonStringEnumConverter<Severity>))]
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// <summary>A single issue found by a rule. <see cref="RuleId"/> is stable across releases.</summary>
public sealed record Finding(string RuleId, Severity Severity, string Title, string Detail, string? Location = null)
{
    /// <summary>Set when a policy suppression applies: its reason. Suppressed findings are kept in JSON/SARIF but do not count.</summary>
    public string? Suppression { get; init; }

    /// <summary>With a baseline: "new" or "existing". Only new findings count toward the exit code.</summary>
    public string? Baseline { get; init; }

    /// <summary>True when the finding counts toward the exit code (not suppressed, and new if a baseline is in use).</summary>
    [JsonIgnore]
    public bool Counts => Suppression is null && Baseline != "existing";
}
