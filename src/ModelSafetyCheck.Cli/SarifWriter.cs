using System.Text;
using System.Text.Json;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Cli;

/// <summary>Writes SARIF 2.1.0 so results show up in GitHub code scanning and other SARIF viewers.</summary>
static class SarifWriter
{
    public static string Write(IReadOnlyList<ScanReport> reports)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            w.WriteStartObject();
            w.WriteString("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
            w.WriteString("version", "2.1.0");
            w.WriteStartArray("runs");
            w.WriteStartObject();

            w.WriteStartObject("tool");
            w.WriteStartObject("driver");
            w.WriteString("name", "modelcheck");
            w.WriteString("version", typeof(SarifWriter).Assembly.GetName().Version?.ToString(3) ?? "0.0.0");
            w.WriteStartArray("rules");
            foreach (var rule in reports.SelectMany(r => r.Findings).GroupBy(f => f.RuleId).OrderBy(g => g.Key))
            {
                w.WriteStartObject();
                w.WriteString("id", rule.Key);
                w.WriteStartObject("shortDescription");
                w.WriteString("text", rule.First().Title);
                w.WriteEndObject();
                w.WriteStartObject("properties");
                w.WriteString("security-severity", SecuritySeverity(rule.Max(f => f.Severity)));
                w.WriteEndObject();
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
            w.WriteEndObject();

            w.WriteStartArray("results");
            foreach (var report in reports)
            {
                foreach (var f in report.Findings)
                {
                    w.WriteStartObject();
                    w.WriteString("ruleId", f.RuleId);
                    w.WriteString("level", f.Severity switch
                    {
                        Severity.Critical or Severity.High => "error",
                        Severity.Medium or Severity.Low => "warning",
                        _ => "note",
                    });
                    w.WriteStartObject("message");
                    w.WriteString("text", $"{f.Title}: {f.Detail}");
                    w.WriteEndObject();
                    WriteLocation(w, report.Target, f.Location);
                    w.WriteEndObject();
                }
                if (report.Error is not null)
                {
                    w.WriteStartObject();
                    w.WriteString("ruleId", "E001");
                    w.WriteString("level", "error");
                    w.WriteStartObject("message");
                    w.WriteString("text", $"Scan failed: {report.Error}");
                    w.WriteEndObject();
                    WriteLocation(w, report.Target, null);
                    w.WriteEndObject();
                }
            }
            w.WriteEndArray();

            w.WriteEndObject();
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    static void WriteLocation(Utf8JsonWriter w, string target, string? location)
    {
        w.WriteStartArray("locations");
        w.WriteStartObject();
        w.WriteStartObject("physicalLocation");
        w.WriteStartObject("artifactLocation");
        w.WriteString("uri", ToUri(target));
        w.WriteEndObject();
        w.WriteEndObject();
        if (location is not null)
        {
            w.WriteStartArray("logicalLocations");
            w.WriteStartObject();
            w.WriteString("fullyQualifiedName", location);
            w.WriteEndObject();
            w.WriteEndArray();
        }
        w.WriteEndObject();
        w.WriteEndArray();
    }

    static string ToUri(string target)
    {
        if (Path.IsPathFullyQualified(target))
        {
            var relative = Path.GetRelativePath(Environment.CurrentDirectory, target);
            return (relative.StartsWith("..", StringComparison.Ordinal) ? new Uri(target).AbsoluteUri : relative).Replace('\\', '/');
        }
        return target.Replace('\\', '/');
    }

    static string SecuritySeverity(Severity severity) => severity switch
    {
        Severity.Critical => "9.5",
        Severity.High => "8.0",
        Severity.Medium => "5.5",
        Severity.Low => "3.0",
        _ => "0.0",
    };
}
