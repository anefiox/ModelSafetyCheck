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
public sealed record Finding(string RuleId, Severity Severity, string Title, string Detail, string? Location = null);
