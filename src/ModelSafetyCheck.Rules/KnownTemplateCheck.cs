using System.Security.Cryptography;
using System.Text;
using ModelSafetyCheck.Core;
using System.Text.RegularExpressions;
using ModelSafetyCheck.Data;
using ModelSafetyCheck.Jinja;

namespace ModelSafetyCheck.Rules;

/// <summary>
/// Rule T010: compares a chat template with the database of official templates. An exact match is
/// reassuring. The interesting case is a near match - an official template with lines added - because
/// that is how poisoned templates are built; the added lines are shown so a human can judge them.
/// </summary>
public static class KnownTemplateCheck
{
    const double CloseMatch = 0.6;
    const double NearCopy = 0.85;
    const int MaxShownLines = 8;

    // Prefer the current version of a template when an earlier revision has the same text.
    static readonly Lazy<Dictionary<string, KnownTemplate>> ByHash = new(() =>
        ReferenceData.KnownTemplates.Templates
            .GroupBy(t => t.NormalizedSha256)
            .ToDictionary(g => g.Key, g => g.OrderBy(t => t.Revision is null ? 0 : 1).First()));

    static readonly Lazy<List<(KnownTemplate Template, Dictionary<string, int> Lines)>> Indexed = new(() =>
        ReferenceData.KnownTemplates.Templates
            .DistinctBy(t => t.NormalizedSha256)
            .Select(t => (t, LineCounts(t.Text)))
            .ToList());

    /// <summary>Whitespace-insensitive hash, so re-indented copies of the same template still match.</summary>
    public static string NormalizedHash(string template)
    {
        var builder = new StringBuilder(template.Length);
        foreach (var c in template)
            if (!char.IsWhiteSpace(c))
                builder.Append(c);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
    }

    public static Finding? Check(string template, string location)
    {
        if (ReferenceData.KnownTemplates.Templates.Count == 0)
            return null;

        if (ByHash.Value.TryGetValue(NormalizedHash(template), out var exact))
            return exact.Revision is null
                ? new Finding("T010", Severity.Info, $"Matches the official {exact.Family} template",
                    $"Identical (ignoring whitespace) to the template in {exact.Source}{(exact.Via is null ? "" : $" ({exact.Via})")}.", location)
                : new Finding("T010", Severity.Info, $"Matches the official {exact.Family} template (earlier version)",
                    $"Identical (ignoring whitespace) to the template in {exact.Source} at revision {exact.Revision[..Math.Min(10, exact.Revision.Length)]} ({exact.Date}). " +
                    "The publisher has since changed it; re-download to get the current version.", location);

        var lines = LineCounts(template);
        var best = Indexed.Value
            .Select(k => (k.Template, Similarity: Similarity(lines, k.Lines), k.Lines))
            .MaxBy(x => x.Similarity);

        if (best.Template is null || best.Similarity < CloseMatch)
            return new Finding("T010", Severity.Info, "Unrecognised chat template",
                "This template does not match any official template in the database. That is normal for fine-tunes and new models; read it with --dump-template if the model will get tools.", location);

        static bool IsProse(string line)
        {
            // Special tokens are markup, and a one-sentence identity ("You are X, trained by Y.") is normal in fine-tunes.
            var text = Regex.Replace(ModelVisibleText(line), @"<\|?[^<>\s]{1,40}\|?>", " ").Trim();
            return TextHeuristics.CountWords(text) >= 8 && !Regex.IsMatch(text, @"^You are [^.!?]{1,100}[.!?]?$", RegexOptions.IgnoreCase);
        }
        var added = Added(lines, best.Lines).OrderByDescending(IsProse).ToList();
        var removed = Added(best.Lines, lines);
        // An edited line (same sentence, reworded) is not injected text: count only words that the closest
        // removed line does not already have.
        int NewWords(string line)
        {
            var words = Regex.Matches(ModelVisibleText(line), @"\p{L}{2,}").Select(m => m.Value.ToLowerInvariant()).ToList();
            var closest = removed.Select(r => Regex.Matches(ModelVisibleText(r), @"\p{L}{2,}").Select(m => m.Value.ToLowerInvariant()).ToHashSet())
                .MaxBy(set => words.Count(set.Contains)) ?? [];
            return words.Count(w => !closest.Contains(w));
        }
        var injectedText = added.Any(l => IsProse(l) && NewWords(l) >= 8);
        var shown = added.Take(MaxShownLines).Select(l => $"\n  + {TextHeuristics.Truncate(l, 140)}");
        var addedText = $"Added lines:{string.Concat(shown)}{(added.Count > MaxShownLines ? $"\n  (+{added.Count - MaxShownLines} more)" : "")}";

        // A near-identical copy with a few added lines is the shape of an injection. A large rewrite is
        // usually a different release of the template (e.g. an older download).
        if (best.Similarity < NearCopy)
            return new Finding("T010", Severity.Info, $"Different version of the {best.Template.Family} template",
                $"{best.Similarity:P0} similar to {best.Template.Source} ({added.Count} line(s) added, {removed.Count} removed). " +
                $"Large differences usually mean a different release of the template, such as an older download. {addedText}", location);

        return new Finding("T010", injectedText ? Severity.Medium : Severity.Info,
            $"Modified copy of the official {best.Template.Family} template",
            $"{best.Similarity:P0} similar to {best.Template.Source}, with {added.Count} line(s) added and {removed.Count} removed. " +
            (injectedText ? "Some added lines contain natural-language text, which is how hidden instructions are injected. " : "") + addedText,
            location);
    }

    /// <summary>Line-level comparison: lines in <paramref name="candidate"/> but not <paramref name="reference"/>, and vice versa.</summary>
    public static (List<string> Added, List<string> Removed, double Similarity) Compare(string candidate, string reference)
    {
        var a = LineCounts(candidate);
        var b = LineCounts(reference);
        return (Added(a, b), Added(b, a), Similarity(a, b));
    }

    /// <summary>What the model would read from one template line: quoted strings and text outside tags. Comments and code are dropped.</summary>
    static string ModelVisibleText(string line)
    {
        var withoutComments = Regex.Replace(line, @"\{#.*?(?:#\}|$)", " ");
        var lex = TemplateLexer.Lex(withoutComments, TemplateDialect.Jinja);
        return string.Join(" ", lex.Segments.Select(s => s.Kind switch
        {
            SegmentKind.Text => s.Raw,
            SegmentKind.Expression or SegmentKind.Statement => string.Join(" ", s.Tokens.Where(t => t.Kind == TokenKind.String).Select(t => t.Value)),
            _ => "",
        }));
    }

    /// <summary>Lines of the template without Jinja comments, which the model never sees (and which may span lines).</summary>
    static Dictionary<string, int> LineCounts(string text)
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var raw in Regex.Replace(text, @"\{#.*?#\}", "", RegexOptions.Singleline).Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length > 0)
                counts[line] = counts.GetValueOrDefault(line) + 1;
        }
        return counts;
    }

    static double Similarity(Dictionary<string, int> a, Dictionary<string, int> b)
    {
        var common = a.Sum(kv => Math.Min(kv.Value, b.GetValueOrDefault(kv.Key)));
        var total = a.Values.Sum() + b.Values.Sum();
        return total == 0 ? 0 : 2.0 * common / total;
    }

    static List<string> Added(Dictionary<string, int> candidate, Dictionary<string, int> reference) =>
        candidate.Where(kv => kv.Value > reference.GetValueOrDefault(kv.Key))
            .SelectMany(kv => Enumerable.Repeat(kv.Key, kv.Value - reference.GetValueOrDefault(kv.Key)))
            .ToList();
}
