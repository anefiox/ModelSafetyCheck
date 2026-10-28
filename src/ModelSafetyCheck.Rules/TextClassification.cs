using ModelSafetyCheck.Core;
using ModelSafetyCheck.Jinja;

namespace ModelSafetyCheck.Rules;

/// <summary>
/// Optional machine-learning check (rule T015). The scanner works without it; the CLI plugs in an ONNX
/// prompt-injection classifier when `--classifier` is used. Keeping only this interface here means the core
/// libraries never depend on ONNX Runtime.
/// </summary>
public interface ITextClassifier
{
    string Name { get; }

    /// <summary>Probability (0–1) that each text is a prompt injection.</summary>
    IReadOnlyList<double> Score(IReadOnlyList<string> texts);
}

public static class TextClassification
{
    /// <summary>Set by the host to enable T015.</summary>
    public static ITextClassifier? Classifier { get; set; }

    /// <summary>Scores at or above this are reported.</summary>
    public static double Threshold { get; set; } = 0.98;

    const int MinWords = 6;

    /// <summary>Prose the model will read from a template: text outside tags and string literals with at least a few words.</summary>
    public static List<string> ModelVisibleProse(string template, TemplateDialect dialect)
    {
        var lex = TemplateLexer.Lex(template, dialect);
        // raise_exception(...) messages are errors for the caller; the model never reads them.
        static IEnumerable<string> Strings(IReadOnlyList<TemplateToken> tokens) =>
            tokens.Where((t, i) => t.Kind == TokenKind.String && !(i >= 2 && tokens[i - 1].Value == "(" && tokens[i - 2].Value == "raise_exception"))
                .Select(t => t.Value);
        return lex.Segments.Where(s => s.Kind == SegmentKind.Text).Select(s => s.Raw)
            .Concat(lex.Segments.Where(s => s.Kind is SegmentKind.Expression or SegmentKind.Statement).SelectMany(s => Strings(s.Tokens)))
            .Select(t => System.Text.RegularExpressions.Regex.Replace(t, @"<\|?[^<>\s]{1,40}\|?>", " ").Trim())
            .Where(t => TextHeuristics.CountWords(t) >= MinWords)
            .Distinct()
            .ToList();
    }

    /// <summary>
    /// The template text worth classifying. Instruction-like text is normal in official templates (tool docs,
    /// developer preambles) and classifiers flag it, so text that also appears in the nearest official template
    /// is skipped, and an exact official match is skipped entirely. Text added by a trigger probe is always included.
    /// </summary>
    public static List<string> TextToClassify(string template, TemplateDialect dialect, IEnumerable<string> probeAdded)
    {
        var (official, exact) = dialect == TemplateDialect.Jinja ? KnownTemplateCheck.NearestOfficial(template) : (null, false);
        if (exact)
            return [];
        var known = official is null ? [] : ModelVisibleProse(official.Text, TemplateDialect.Jinja).ToHashSet(StringComparer.Ordinal);
        return ModelVisibleProse(template, dialect).Where(p => !known.Contains(p))
            .Concat(probeAdded.Where(p => TextHeuristics.CountWords(p) >= MinWords))
            .Distinct()
            .ToList();
    }

    /// <summary>T015: texts the classifier rates as prompt injection.</summary>
    public static IEnumerable<Finding> Check(IReadOnlyList<string> texts, string location, string what)
    {
        if (Classifier is null || texts.Count == 0)
            yield break;
        var scores = Classifier.Score(texts);
        var hits = texts.Zip(scores).Where(x => x.Second >= Threshold).OrderByDescending(x => x.Second).ToList();
        if (hits.Count == 0)
            yield break;
        yield return new Finding("T015", Severity.Medium, $"Classifier rates text in the {what} as prompt injection",
            $"{Classifier.Name} scored {hits.Count} passage(s) at or above {Threshold:P0}. A classifier can be wrong either way; read the text:" +
            string.Concat(hits.Take(4).Select(h => $"\n  - {h.Second:P1}: \"{TextHeuristics.Truncate(h.First, 160)}\"")),
            location);
    }
}
