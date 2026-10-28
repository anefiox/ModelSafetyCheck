using System.Text.Json;
using ModelSafetyCheck.Data;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Tests;

/// <summary>
/// Byte-for-byte comparison with real jinja2 (configured like Hugging Face). Needs the reference file from
/// tools/render-fidelity/render_reference.py in MODELCHECK_FIDELITY_FILE; CI produces it, local runs skip it.
/// </summary>
public class RenderFidelityTests
{
    [Fact]
    public void Official_templates_render_exactly_like_jinja2()
    {
        var path = Environment.GetEnvironmentVariable("MODELCHECK_FIDELITY_FILE");
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
            return;

        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var mismatches = new List<string>();
        var compared = 0;
        foreach (var t in ReferenceData.KnownTemplates.Templates)
        {
            var key = OfficialTemplateTests.Id(t);
            if (!doc.RootElement.TryGetProperty(key, out var expected) || expected.ValueKind != JsonValueKind.String)
                continue;
            var actual = TemplateExplainer.Explain(t.Text).Prompt;
            compared++;
            if (actual != expected.GetString())
                mismatches.Add($"{key}: first difference at {FirstDifference(actual ?? "", expected.GetString()!)}");
        }
        Assert.True(mismatches.Count == 0, string.Join("\n", mismatches));
    }

    static string FirstDifference(string a, string b)
    {
        var i = 0;
        while (i < a.Length && i < b.Length && a[i] == b[i]) i++;
        string Around(string s) => System.Text.Json.JsonSerializer.Serialize(s.Substring(Math.Max(0, i - 20), Math.Min(50, s.Length - Math.Max(0, i - 20))));
        return $"char {i}: ours {Around(a)} vs jinja2 {Around(b)}";
    }
}
