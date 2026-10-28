using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Jinja;

namespace ModelSafetyCheck.Rules;

/// <summary>
/// Static analysis of chat templates (rules T002-T011). Templates run on every prompt, so they are
/// treated as code: we look for sandbox escapes, hidden instructions and conditional triggers.
/// Nothing here renders or evaluates the template.
/// </summary>
public static partial class TemplateAnalyzer
{
    public const int LargeTemplateChars = 256 * 1024;
    const int MaxEvidence = 5;

    static readonly HashSet<string> EscapeNames = ["popen", "subprocess", "__import__", "importlib", "builtins", "__builtins__", "func_globals", "f_globals", "gi_frame", "co_code"];
    /// <summary>Python dunders used to walk from any object to builtins/os. Other dunder-shaped names are harmless.</summary>
    static readonly HashSet<string> DangerousDunders =
    [
        "__class__", "__base__", "__bases__", "__mro__", "__subclasses__", "__globals__", "__builtins__", "__import__", "__init__",
        "__dict__", "__getattribute__", "__getitem__", "__code__", "__func__", "__self__", "__module__", "__loader__", "__spec__",
        "__reduce__", "__reduce_ex__", "__closure__", "__defaults__", "__kwdefaults__", "__name__", "__qualname__", "__call__", "__new__",
    ];

    /// <summary>Mode switches that templates legitimately look for in the system prompt.</summary>
    static readonly string[] ControlPhrases =
        ["detailed thinking on", "detailed thinking off", "reasoning strength", "reasoning effort", "reasoning:", "thinking mode", "/think", "/no_think", "/nothink"];

    static readonly HashSet<string> GadgetGlobals = ["lipsum", "cycler", "joiner", "self", "config", "request", "url_for", "get_flashed_messages"];
    static readonly HashSet<string> DangerousCalls = ["eval", "exec", "open", "system", "compile", "getattr", "setattr", "globals", "locals", "vars", "mro"];
    static readonly HashSet<string> LoaderStatements = ["include", "import", "extends", "from"];
    static readonly HashSet<string> MatchMethods = ["startswith", "endswith", "find", "rfind", "index", "rindex", "count", "search", "match", "contains", "hasPrefix", "hasSuffix", "__contains__"];
    static readonly HashSet<string> MatchTests = ["equalto", "eq", "==", "search", "match", "in", "sameas", "contains"];
    static readonly HashSet<string> GoCompareFuncs = ["eq", "ne", "lt", "le", "gt", "ge", "contains", "hasPrefix", "hasSuffix"];
    static readonly HashSet<string> ComparisonOps = ["==", "!=", "<", ">", "<=", ">="];
    static readonly HashSet<string> ContentNames = new(StringComparer.OrdinalIgnoreCase) { "content", "messages", "message", "prompt", "text", "query", "input", "user_input", "last_message", "response", "system_message" };
    static readonly HashSet<string> TimeNames = ["strftime_now", "now", "datetime", "utcnow", "today", "random", "randint", "currentDate"];
    static readonly HashSet<string> Roles = new(StringComparer.OrdinalIgnoreCase) { "system", "user", "assistant", "tool", "ipython", "function", "developer", "model", "human", "bot", "gpt", "observation", "tool_response", "tool_call", "tool_calls" };

    /// <summary>Single words that legitimate templates commonly test for (keys, content types, mode switches).</summary>
    static readonly HashSet<string> CommonWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "content", "role", "type", "text", "image", "image_url", "video", "video_url", "audio", "input_audio", "file", "name", "function", "arguments",
        "reasoning_content", "reasoning", "thinking", "thought", "analysis", "final", "commentary", "parameters", "description", "properties", "required",
        "json", "string", "object", "array", "items", "enum", "null", "true", "false", "python", "code_interpreter", "brave_search", "wolfram_alpha",
        "tools", "tool_call_id", "id", "/think", "/no_think", "/nothink", "/system_override", "channel", "recipient", "documents", "title",
    };

    [GeneratedRegex(@"^(?:\d{4}-\d{2}-\d{2}.*|\d{1,2} [A-Za-z]{3,9} \d{4}|[A-Za-z]{3,9} \d{1,2},? \d{4}|\d{1,2}/\d{1,2}/\d{2,4})$")]
    private static partial Regex DateRegex();

    [GeneratedRegex(@"^__\w+__$")]
    private static partial Regex DunderRegex();

    [GeneratedRegex(@"__\w+__")]
    private static partial Regex DunderInStringRegex();

    [GeneratedRegex(@"^[\p{L}\p{N}_\-.:/]+$")]
    private static partial Regex WordRegex();

    enum LiteralClass { Markup, Role, Word, Phrase, Date }

    /// <summary>Analyses a chat template. <paramref name="location"/> names where it came from (e.g. "kv:tokenizer.chat_template").</summary>
    public static List<Finding> Analyze(string template, TemplateDialect dialect, string location)
    {
        var findings = new List<Finding>();
        var lex = TemplateLexer.Lex(template, dialect);

        if (template.Length > LargeTemplateChars)
            findings.Add(new("T008", Severity.Medium, "Unusually large chat template",
                $"The template is {template.Length:N0} characters. Typical chat templates are under 20,000. Large templates are hard to review by hand.", location));
        if (lex.Errors.Count > 0)
            findings.Add(new("T008", Severity.Medium, "Template could not be fully parsed",
                $"{lex.Errors[0].Message} at character {lex.Errors[0].Offset}. Runners may interpret it differently from this scanner.", location));

        var tags = lex.Segments.Where(s => s.Kind is SegmentKind.Expression or SegmentKind.Statement).ToList();
        if (dialect == TemplateDialect.Jinja)
        {
            CheckSandboxEscapes(tags, template, location, findings);
            CheckResourceExhaustion(tags, location, findings);
        }
        CheckTriggers(tags, dialect, template, location, findings);
        CheckTime(tags, dialect, template, location, findings);

        var literals = lex.Segments.Where(s => s.Kind == SegmentKind.Text).Select(s => s.Raw)
            .Concat(tags.SelectMany(s => s.Tokens).Where(t => t.Kind == TokenKind.String).Select(t => t.Value))
            .ToList();
        AnalyzeText(literals, location, findings, "template");
        return Escalate(findings);
    }

    /// <summary>
    /// A trigger alone, or a link alone, is common in community templates. A trigger together with a
    /// payload (instructions, links, hidden text) is the shape of a poisoned template, so it rates higher.
    /// </summary>
    static List<Finding> Escalate(List<Finding> findings)
    {
        var trigger = findings.Any(f => f.RuleId == "T005" && f.Severity >= Severity.Medium);
        var instructions = findings.Any(f => f.RuleId == "T004" && f.Severity >= Severity.Medium);
        var links = findings.Any(f => f.RuleId == "T003");
        var hidden = findings.Any(f => f.RuleId == "T007" && f.Severity >= Severity.High);

        return findings.Select(f => f switch
        {
            { RuleId: "T005", Severity: Severity.Medium } when instructions || links || hidden =>
                f with { Severity = Severity.High, Detail = f.Detail + "\nRaised to High: the template also contains instructions, links or hidden text that a trigger could switch on." },
            { RuleId: "T003", Severity: Severity.Low } when trigger || instructions =>
                f with { Severity = Severity.Medium },
            _ => f,
        }).ToList();
    }

    /// <summary>Content rules (T003, T004, T007, T009) for plain text such as an Ollama SYSTEM layer.</summary>
    public static List<Finding> AnalyzePlainText(string text, string location)
    {
        var findings = new List<Finding>();
        AnalyzeText([text], location, findings, "system prompt");
        return findings;
    }

    static void AnalyzeText(List<string> literals, string location, List<Finding> findings, string what)
    {
        var all = string.Join("\n", literals);

        var invisible = TextHeuristics.ScanInvisible(all);
        if (invisible.Any)
            findings.Add(new("T007", invisible.Severity, $"Invisible Unicode in {what}",
                $"Found {invisible.Describe()}. Hidden characters let a {what} carry instructions a human reviewer cannot see.", location));

        var markup = literals.SelectMany(TextHeuristics.FindActiveMarkup).Distinct().ToList();
        if (markup.Count > 0)
            findings.Add(new("T003", Severity.High, $"Active HTML/markdown in {what}",
                $"The {what} contains markup that makes a client fetch a URL when rendered (a data-exfiltration vector): {Evidence(markup)}", location));

        var urls = literals.SelectMany(TextHeuristics.FindUrls).Distinct().ToList();
        if (urls.Count > 0)
            findings.Add(new("T003", Severity.Low, $"URL in {what}",
                $"The {what} contains URLs the model will see. Often an author's own link; poisoned templates use this to make the model serve attacker links: {Evidence(urls)}", location));

        var phrases = literals.SelectMany(TextHeuristics.FindInstructionPhrases).ToList();
        if (phrases.Count > 0)
        {
            var severity = phrases.Max(p => p.Severity);
            var evidence = phrases.Select(p => $"{p.Description}: \"{TextHeuristics.Truncate(p.Match, 80)}\"").Distinct().ToList();
            findings.Add(new("T004", severity, $"Suspicious instructions in {what}",
                $"Text the model will read contains phrases typical of injected instructions: {Evidence(evidence)}", location));
        }

        var fixedText = literals.Select(l => l.Trim()).Where(l => TextHeuristics.CountWords(l) >= 8).Distinct().ToList();
        if (fixedText.Count > 0)
            findings.Add(new("T009", Severity.Info, $"{Capitalize(what)} adds fixed text the model will read",
                $"Review this text; it is sent to the model with your messages: {Evidence(fixedText.Select(t => $"\"{TextHeuristics.Truncate(t, 160)}\"").ToList())}", location));
    }

    static void CheckSandboxEscapes(List<TemplateSegment> tags, string template, string location, List<Finding> findings)
    {
        var critical = new List<string>();
        var high = new List<string>();
        foreach (var segment in tags)
        {
            if (segment.Kind == SegmentKind.Statement && segment.Keyword is { } keyword && LoaderStatements.Contains(keyword))
                high.Add($"'{keyword}' statement loads other templates: {Snippet(template, segment.Offset)}");

            var toks = segment.Tokens;
            for (var i = 0; i < toks.Count; i++)
            {
                var t = toks[i];
                var prev = i > 0 ? toks[i - 1].Value : null;
                var next = i + 1 < toks.Count ? toks[i + 1].Value : null;
                if (t.Kind == TokenKind.Name)
                {
                    if (DangerousDunders.Contains(t.Value) || EscapeNames.Contains(t.Value))
                        critical.Add($"'{t.Value}': {Snippet(template, t.Offset)}");
                    else if (DunderRegex().IsMatch(t.Value) && prev == ".")
                        high.Add($"attribute '{t.Value}': {Snippet(template, t.Offset)}");
                    else if (prev != "." && next != "=" && GadgetGlobals.Contains(t.Value) && (next is "." or "(" or "|" or "["))
                        high.Add($"global '{t.Value}': {Snippet(template, t.Offset)}");
                    else if (DangerousCalls.Contains(t.Value) && next == "(")
                        high.Add($"call '{t.Value}(': {Snippet(template, t.Offset)}");
                    else if (t.Value == "attr" && prev == "|")
                        high.Add($"'|attr' filter: {Snippet(template, t.Offset)}");
                }
                else if (t.Kind == TokenKind.String)
                {
                    // Strings matter for `|attr('__globals__')`. Harmless dunder-shaped strings (e.g. '__sentinel__') are ignored.
                    if (DunderInStringRegex().Matches(t.Value).Any(m => DangerousDunders.Contains(m.Value)))
                        critical.Add($"string '{TextHeuristics.Truncate(t.Value, 40)}': {Snippet(template, t.Offset)}");
                    else if (t.Value.Length > 2 && DangerousDunders.Any(d => d != t.Value &&
                                 ((t.Value.StartsWith("__", StringComparison.Ordinal) && d.StartsWith(t.Value, StringComparison.Ordinal)) ||
                                  (t.Value.EndsWith("__", StringComparison.Ordinal) && d.EndsWith(t.Value, StringComparison.Ordinal)))))
                        high.Add($"string fragment of a dangerous name '{TextHeuristics.Truncate(t.Value, 40)}': {Snippet(template, t.Offset)}");
                }
            }
        }

        if (critical.Count + high.Count == 0)
            return;
        findings.Add(new("T002", critical.Count > 0 ? Severity.Critical : Severity.High, "Jinja sandbox-escape primitives in chat template",
            "Chat templates run on every prompt. These constructs are used to break out of Jinja and run commands on your machine " +
            "(e.g. CVE-2024-34359 'Llama Drama' in llama-cpp-python). Legitimate chat templates do not need them: " + Evidence([.. critical, .. high]),
            location));
    }

    static void CheckResourceExhaustion(List<TemplateSegment> tags, string location, List<Finding> findings)
    {
        var evidence = tags.SelectMany(s => s.Tokens)
            .Where(t => t.Value == "**" ||
                        (t.Kind == TokenKind.Number && double.TryParse(t.Value.Replace("_", ""), System.Globalization.CultureInfo.InvariantCulture, out var n) && n >= 100_000_000))
            .Select(t => $"'{t.Value}'")
            .Distinct()
            .ToList();
        if (evidence.Count > 0)
            findings.Add(new("T011", Severity.Medium, "Possible resource exhaustion in template",
                $"Exponentiation or very large numbers can make template rendering hang or exhaust memory on every prompt: {Evidence(evidence)}", location));
    }

    /// <summary>A string literal that a template compares message content (or anything) against.</summary>
    sealed record ComparedLiteral(string Value, LiteralClass Class, bool SubstringTest, bool SearchesContent, TemplateSegment Segment);

    static IEnumerable<ComparedLiteral> ComparedLiterals(List<TemplateSegment> tags, TemplateDialect dialect)
    {
        foreach (var segment in tags)
        {
            var toks = segment.Tokens;
            var goCompare = dialect == TemplateDialect.GoTemplate && toks.Any(t => t.Kind == TokenKind.Name && GoCompareFuncs.Contains(t.Value));

            for (var i = 0; i < toks.Count; i++)
            {
                if (toks[i].Kind != TokenKind.String)
                    continue;
                var value = toks[i].Value;
                var cls = Classify(value);
                if (cls is LiteralClass.Markup or LiteralClass.Role)
                    continue;

                var prev = i > 0 ? toks[i - 1].Value : null;
                var next = i + 1 < toks.Count ? toks[i + 1].Value : null;
                var afterNext = i + 2 < toks.Count ? toks[i + 2].Value : null;
                var inTest = next == "in" || (next == "not" && afterNext == "in");
                var methodTest = prev == "(" && i >= 2 && toks[i - 2].Kind == TokenKind.Name && MatchMethods.Contains(toks[i - 2].Value);
                var filterTest = prev == "," && i >= 2 && toks[i - 2].Kind == TokenKind.String && MatchTests.Contains(toks[i - 2].Value);
                var substringTest = inTest || methodTest || filterTest || goCompare;

                // Which tokens hold the thing being searched: the right side of `in`, the receiver of a
                // method, or the whole tag for filters and Go functions.
                var operand = inTest ? toks.Skip(i + 2).TakeWhile(t => t.Value is not ("and" or "or" or "if" or "else"))
                    : methodTest ? toks.Take(i - 2).Reverse().Take(8)
                    : toks;
                var searchesContent = operand.Any(t => t.Kind is TokenKind.Name or TokenKind.String && ContentNames.Contains(t.Value));
                var comparison = (prev is not null && ComparisonOps.Contains(prev)) || (next is not null && ComparisonOps.Contains(next));
                if (substringTest || comparison)
                    yield return new ComparedLiteral(value, cls, substringTest, searchesContent, segment);
            }
        }
    }

    /// <summary>
    /// Text worth putting into a message to see whether the template reacts: phrases, unusual words and
    /// dates that the template compares against. Used by the explainer's trigger probes.
    /// </summary>
    public static List<string> TriggerCandidates(string template, TemplateDialect dialect)
    {
        var tags = TemplateLexer.Lex(template, dialect).Segments.Where(s => s.Kind is SegmentKind.Expression or SegmentKind.Statement).ToList();
        return ComparedLiterals(tags, dialect)
            .Where(c => !ControlPhrases.Any(p => c.Value.Trim().Equals(p, StringComparison.OrdinalIgnoreCase)))
            .Where(c => c.Class is LiteralClass.Phrase or LiteralClass.Date ||
                        (c.SubstringTest && c.SearchesContent && !CommonWords.Contains(c.Value) && !ContentNames.Contains(c.Value)))
            .Select(c => c.Value)
            .Distinct()
            .Take(40)
            .ToList();
    }

    static void CheckTriggers(List<TemplateSegment> tags, TemplateDialect dialect, string template, string location, List<Finding> findings)
    {
        var phrases = new List<string>();
        var words = new List<string>();
        var dates = new List<string>();
        foreach (var c in ComparedLiterals(tags, dialect))
        {
            var value = c.Value;
            var evidence = $"\"{TextHeuristics.Truncate(value, 60)}\": {Snippet(template, c.Segment.Offset)}";
            if (c.Class == LiteralClass.Date)
                dates.Add(evidence);
            else if (ControlPhrases.Any(p => value.Trim().Equals(p, StringComparison.OrdinalIgnoreCase)))
                continue;
            else if (c.Class == LiteralClass.Phrase)
                phrases.Add(evidence);
            else if (c.SubstringTest && c.SearchesContent && !CommonWords.Contains(value) && !ContentNames.Contains(value))
                words.Add(evidence);
        }

        // Medium on its own; Escalate() raises it to High when the template also carries a payload.
        if (phrases.Count > 0)
            findings.Add(new("T005", Severity.Medium, "Template behaves differently when a message contains specific text",
                "Poisoned templates hide instructions that only activate on a trigger phrase, so the model looks normal in testing. " +
                "Some community templates also route on message content; check what these branches emit: " + Evidence(phrases),
                location));
        if (words.Count > 0)
            findings.Add(new("T005", Severity.Info, "Template tests message content for keywords",
                "Usually key or content-type checks; listed for review: " + Evidence(words), location));
        if (dates.Count > 0)
            findings.Add(new("T006", Severity.High, "Template compares against a specific date",
                "A template that behaves differently after a given date is a time bomb: " + Evidence(dates), location));
    }

    static void CheckTime(List<TemplateSegment> tags, TemplateDialect dialect, string template, string location, List<Finding> findings)
    {
        var conditional = new List<string>();
        var used = false;
        foreach (var segment in tags)
        {
            var toks = segment.Tokens;
            var timeIndexes = Enumerable.Range(0, toks.Count)
                .Where(i => toks[i].Kind == TokenKind.Name && TimeNames.Contains(toks[i].Value) && (i == 0 || toks[i - 1].Value != "."))
                .ToList();
            if (timeIndexes.Count == 0)
                continue;
            used = true;

            var isCondition = toks.Any(t => t.Kind == TokenKind.Name && t.Value is "if" or "elif");
            var compares = toks.Any(t => t.Kind == TokenKind.Operator && ComparisonOps.Contains(t.Value)) ||
                           (dialect == TemplateDialect.GoTemplate && toks.Any(t => t.Kind == TokenKind.Name && GoCompareFuncs.Contains(t.Value)));
            var onlyDefinedCheck = timeIndexes.All(i => i + 1 < toks.Count && toks[i + 1].Value == "is");
            if (isCondition && compares && !onlyDefinedCheck)
                conditional.Add(Snippet(template, segment.Offset));
        }

        if (conditional.Count > 0)
            findings.Add(new("T006", Severity.High, "Template branches on the current date, time or randomness",
                "Behaviour that depends on the clock or chance can hide from testing (time bombs, intermittent triggers): " + Evidence(conditional), location));
        else if (used)
            findings.Add(new("T006", Severity.Info, "Template reads the current date or time",
                "Common and usually benign (e.g. Llama 3 inserts today's date into the system prompt).", location));
    }

    static LiteralClass Classify(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length == 0) return LiteralClass.Markup;
        if (Roles.Contains(trimmed)) return LiteralClass.Role;
        if (DateRegex().IsMatch(trimmed)) return LiteralClass.Date;
        if (trimmed.IndexOfAny(['<', '>', '[', ']', '|', '{', '}']) >= 0) return LiteralClass.Markup;
        if (TextHeuristics.CountWords(trimmed) == 0) return LiteralClass.Markup;
        if (WordRegex().IsMatch(trimmed)) return LiteralClass.Word;
        return trimmed.Any(char.IsWhiteSpace) ? LiteralClass.Phrase : LiteralClass.Markup;
    }

    static string Snippet(string template, int offset)
    {
        var start = Math.Max(0, offset);
        var length = Math.Min(80, template.Length - start);
        return $"`{TextHeuristics.Truncate(template.Substring(start, length), 80)}`";
    }

    static string Evidence(List<string> items)
    {
        var shown = items.Take(MaxEvidence).Select(i => "\n  - " + i);
        var more = items.Count > MaxEvidence ? $"\n  (+{items.Count - MaxEvidence} more)" : "";
        return string.Concat(shown) + more;
    }

    static string Capitalize(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];
}
