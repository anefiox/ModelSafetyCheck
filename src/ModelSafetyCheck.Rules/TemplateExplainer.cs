using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Jinja;
using ModelSafetyCheck.Jinja.Render;

namespace ModelSafetyCheck.Rules;

public sealed record ExplainOptions
{
    public string BosToken { get; init; } = "<s>";
    public string EosToken { get; init; } = "</s>";

    /// <summary>Custom conversation (role/content dicts). The sample conversation is used when null.</summary>
    public IReadOnlyList<Dictionary<string, object?>>? Messages { get; init; }

    public DateTimeOffset Now { get; init; } = new(2026, 1, 15, 12, 0, 0, TimeSpan.Zero);
}

/// <summary>What changes when a probe (trigger phrase or date) is present.</summary>
public sealed record ProbeResult(string Probe, string Where, IReadOnlyList<string> Added, IReadOnlyList<string> Removed)
{
    public bool Changed => Added.Count + Removed.Count > 0;
}

public sealed record Explanation(
    string? Prompt,
    string? PromptWithTools,
    string? Error,
    IReadOnlyList<ProbeResult> Probes,
    IReadOnlyList<string> Notes,
    int ProbesRun = 0);

/// <summary>
/// Renders a chat template in the safe evaluator to show exactly what the model receives, then re-renders it
/// with each phrase or date the template compares against. Text that appears only when a probe is present
/// is a trigger with a payload: hard evidence rather than a heuristic (rule T013).
/// </summary>
public static partial class TemplateExplainer
{
    const string Neutral = "Hello there.";
    const string ProbeSlot = "\u0001PROBE\u0001";

    [GeneratedRegex(@"\d")]
    private static partial Regex DigitRegex();

    [GeneratedRegex(@"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\b|\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*\b")]
    private static partial Regex DateWordRegex();

    static readonly Dictionary<string, object?> SampleTool = new()
    {
        ["type"] = "function",
        ["function"] = new Dictionary<string, object?>
        {
            ["name"] = "get_weather",
            ["description"] = "Get the current weather for a city.",
            ["parameters"] = new Dictionary<string, object?>
            {
                ["type"] = "object",
                ["properties"] = new Dictionary<string, object?> { ["city"] = new Dictionary<string, object?> { ["type"] = "string" } },
                ["required"] = new List<object?> { "city" },
            },
        },
    };

    static List<Dictionary<string, object?>> SampleConversation(bool withSystem, string systemExtra, string userText)
    {
        var messages = new List<Dictionary<string, object?>>();
        if (withSystem)
            messages.Add(new() { ["role"] = "system", ["content"] = "You are a helpful assistant." + systemExtra });
        messages.Add(new() { ["role"] = "user", ["content"] = "What is the capital of France?" });
        messages.Add(new() { ["role"] = "assistant", ["content"] = "The capital of France is Paris." });
        messages.Add(new() { ["role"] = "user", ["content"] = userText });
        return messages;
    }

    public static Explanation Explain(string template, ExplainOptions? options = null)
    {
        options ??= new ExplainOptions();
        var notes = new List<string>();

        // Some templates (e.g. Gemma 2, early Mistral) reject a system message; fall back to none.
        var withSystem = true;
        var prompt = Render(template, options, Conversation(options, true, "", Neutral), tools: false, options.Now);
        if (!prompt.Success && prompt.Raised && options.Messages is null)
        {
            var retry = Render(template, options, Conversation(options, false, "", Neutral), tools: false, options.Now);
            if (retry.Success)
            {
                withSystem = false;
                notes.Add("The template rejects system messages, so the sample conversation has none.");
                prompt = retry;
            }
        }
        if (!prompt.Success)
            return new Explanation(null, null, prompt.Error, [], notes);

        var withTools = template.Contains("tools", StringComparison.Ordinal)
            ? Render(template, options, Conversation(options, withSystem, "", Neutral), tools: true, options.Now)
            : null;
        if (withTools is { Success: false })
            notes.Add($"Rendering with a tool definition failed: {withTools.Error}");

        var probes = new List<ProbeResult>();
        if (options.Messages is null)
        {
            foreach (var candidate in TemplateAnalyzer.TriggerCandidates(template, TemplateDialect.Jinja))
            {
                probes.Add(Probe(template, options, withSystem, candidate, inSystem: false));
                if (withSystem)
                    probes.Add(Probe(template, options, withSystem, candidate, inSystem: true));
            }
            if (template.Contains("strftime_now", StringComparison.Ordinal))
                probes.AddRange(DateProbes(template, options, withSystem));
        }

        return new Explanation(prompt.Output, withTools?.Output, null, probes.Where(p => p.Changed).ToList(), notes, probes.Count);
    }

    static List<Dictionary<string, object?>> Conversation(ExplainOptions options, bool withSystem, string systemExtra, string userText) =>
        options.Messages?.ToList() ?? SampleConversation(withSystem, systemExtra, userText);

    static RenderResult Render(string template, ExplainOptions options, List<Dictionary<string, object?>> messages, bool tools, DateTimeOffset now)
    {
        var context = new Dictionary<string, object?>
        {
            ["messages"] = messages,
            ["add_generation_prompt"] = true,
            ["bos_token"] = options.BosToken,
            ["eos_token"] = options.EosToken,
        };
        if (tools)
            context["tools"] = new List<object?> { SampleTool };
        return JinjaRenderer.Render(template, context, new RenderOptions { Now = now });
    }

    /// <summary>Renders with the neutral text and with the candidate in the same place, then diffs with the candidate masked out.</summary>
    static ProbeResult Probe(string template, ExplainOptions options, bool withSystem, string candidate, bool inSystem)
    {
        string? Run(string text)
        {
            var messages = inSystem
                ? SampleConversation(withSystem, " " + text, Neutral)
                : SampleConversation(withSystem, "", text + " Thanks. And Germany?");
            var result = Render(template, options, messages, tools: false, options.Now);
            return result.Output ?? $"[render error: {result.Error}]";
        }

        var baseline = Run(ProbeSlot);
        var probed = Run(candidate);
        if (baseline is null || probed is null)
            return new ProbeResult(candidate, inSystem ? "system message" : "user message", [], []);

        // Mask the candidate wherever the template echoed it (in any letter case), so only template-added text differs.
        var masked = Regex.Replace(probed, Regex.Escape(candidate), ProbeSlot, RegexOptions.IgnoreCase);
        var (added, removed) = LineDiff(masked, baseline);
        return new ProbeResult(candidate, inSystem ? "system message" : "user message", added, removed);
    }

    static IEnumerable<ProbeResult> DateProbes(string template, ExplainOptions options, bool withSystem)
    {
        var messages = SampleConversation(withSystem, "", Neutral);
        var baseline = Render(template, options, messages, tools: false, options.Now).Output;
        if (baseline is null)
            yield break;

        var dates = new List<DateTimeOffset> { options.Now.AddDays(1), options.Now.AddMonths(6), options.Now.AddYears(1), options.Now.AddYears(3) };
        foreach (var literal in TemplateAnalyzer.TriggerCandidates(template, TemplateDialect.Jinja))
            if (DateTimeOffset.TryParse(literal, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var d))
                dates.AddRange([d.AddDays(-1), d, d.AddDays(1)]);

        // Dates are printed by legitimate templates ("Today Date: ..."), so digits and month/day names are masked.
        static string Mask(string s) => DateWordRegex().Replace(DigitRegex().Replace(s, "0"), "D");
        foreach (var date in dates.Distinct())
        {
            var output = Render(template, options, messages, tools: false, date).Output;
            if (output is null) continue;
            var (added, removed) = LineDiff(Mask(output), Mask(baseline));
            yield return new ProbeResult($"date {date:yyyy-MM-dd}", "clock", added, removed);
        }
    }

    [GeneratedRegex(@"<\|?[^<>\s]{1,40}\|?>|\s+|[^\s<]+|<")]
    private static partial Regex DiffTokenRegex();

    /// <summary>
    /// Word-level diff (longest common subsequence over words and special tokens), returning the runs of text
    /// only in <paramref name="candidate"/> (added) and only in <paramref name="baseline"/> (removed).
    /// </summary>
    static (List<string> Added, List<string> Removed) LineDiff(string candidate, string baseline)
    {
        var a = DiffTokenRegex().Matches(candidate).Select(m => m.Value).ToArray();
        var b = DiffTokenRegex().Matches(baseline).Select(m => m.Value).ToArray();
        if ((long)a.Length * b.Length > 16_000_000)
            return candidate == baseline ? ([], []) : (["(output too large to diff)"], []);

        // Trim the common prefix and suffix first; probes usually change a small region.
        var prefix = 0;
        while (prefix < a.Length && prefix < b.Length && a[prefix] == b[prefix]) prefix++;
        var suffix = 0;
        while (suffix < a.Length - prefix && suffix < b.Length - prefix && a[^(suffix + 1)] == b[^(suffix + 1)]) suffix++;
        var x = a[prefix..^suffix];
        var y = b[prefix..^suffix];

        var lcs = new int[x.Length + 1, y.Length + 1];
        for (var i = x.Length - 1; i >= 0; i--)
            for (var j = y.Length - 1; j >= 0; j--)
                lcs[i, j] = x[i] == y[j] ? lcs[i + 1, j + 1] + 1 : Math.Max(lcs[i + 1, j], lcs[i, j + 1]);

        var added = new List<string>();
        var removed = new List<string>();
        var addRun = new System.Text.StringBuilder();
        var removeRun = new System.Text.StringBuilder();
        void Flush()
        {
            if (addRun.ToString().Trim() is { Length: > 0 } add) added.Add(add.Replace(ProbeSlot, "«probe»"));
            if (removeRun.ToString().Trim() is { Length: > 0 } rem) removed.Add(rem.Replace(ProbeSlot, "«probe»"));
            addRun.Clear();
            removeRun.Clear();
        }
        int p = 0, q = 0;
        while (p < x.Length || q < y.Length)
        {
            if (p < x.Length && q < y.Length && x[p] == y[q]) { Flush(); p++; q++; }
            else if (q >= y.Length || (p < x.Length && lcs[p + 1, q] >= lcs[p, q + 1])) addRun.Append(x[p++]);
            else removeRun.Append(y[q++]);
        }
        Flush();
        return (added, removed);
    }

    /// <summary>T013: probes that made the template add text. Prose or links are High; markup-only changes (e.g. thinking tags) are Info.</summary>
    public static IEnumerable<Finding> Findings(Explanation explanation, string location)
    {
        foreach (var probe in explanation.Probes)
        {
            var added = string.Join(" ", probe.Added);
            var visible = Regex.Replace(added, @"<\|?[^<>\s]{1,40}\|?>|\[/?[A-Z_]{2,20}\]", " ");
            var payload = TextHeuristics.CountWords(visible) >= 4 || TextHeuristics.FindUrls(added).Any();
            var severity = payload ? Severity.High : Severity.Info;
            var shown = string.Concat(probe.Added.Take(5).Select(l => $"\n  + {TextHeuristics.Truncate(l, 160)}")) +
                        string.Concat(probe.Removed.Take(3).Select(l => $"\n  - {TextHeuristics.Truncate(l, 160)}"));
            yield return new Finding("T013", severity,
                probe.Where == "clock" ? $"Template output changes on {probe.Probe}" : $"Template output changes when the {probe.Where} contains \"{TextHeuristics.Truncate(probe.Probe, 40)}\"",
                (payload
                    ? "Rendering the template in the sandbox shows it adds text only when this is present: a trigger with a payload. "
                    : "Rendering shows a formatting-only change, which is typical of mode switches. ") +
                $"Run `modelcheck explain` to see the full prompt. Changes:{shown}",
                location);
        }
    }
}
