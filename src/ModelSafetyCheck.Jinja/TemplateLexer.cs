using System.Text;
using System.Text.RegularExpressions;

namespace ModelSafetyCheck.Jinja;

public enum TemplateDialect
{
    /// <summary>Jinja2, as embedded in GGUF files and Hugging Face tokenizer configs.</summary>
    Jinja,

    /// <summary>Go text/template, as used by Ollama's template layer.</summary>
    GoTemplate,
}

public enum SegmentKind
{
    Text,
    Comment,
    Expression,
    Statement,
}

public enum TokenKind
{
    Name,
    String,
    Number,
    Operator,
}

public sealed record TemplateToken(TokenKind Kind, string Value, int Offset);

public sealed record TemplateSegment(SegmentKind Kind, string Raw, int Offset, IReadOnlyList<TemplateToken> Tokens)
{
    /// <summary>First name inside a tag, e.g. "if", "for", "set", "include".</summary>
    public string? Keyword => Tokens.Count > 0 && Tokens[0].Kind == TokenKind.Name ? Tokens[0].Value : null;
}

public sealed record LexError(string Message, int Offset);

public sealed class LexResult
{
    public List<TemplateSegment> Segments { get; } = [];
    public List<LexError> Errors { get; } = [];
}

/// <summary>
/// Splits a template into text, comments and tags, and tokenizes the inside of each tag.
/// It is used to analyse templates and never evaluates anything.
/// </summary>
public static partial class TemplateLexer
{
    static readonly string[] TwoCharOperators = ["==", "!=", "<=", ">=", "//", "**", ":="];

    [GeneratedRegex(@"\{%[-+]?\s*endraw\s*[-+]?%\}")]
    private static partial Regex EndRawRegex();

    public static LexResult Lex(string source, TemplateDialect dialect)
    {
        var result = new LexResult();
        var text = new StringBuilder();
        var textStart = 0;
        var i = 0;

        void FlushText(int next)
        {
            if (text.Length > 0)
                result.Segments.Add(new TemplateSegment(SegmentKind.Text, text.ToString(), textStart, []));
            text.Clear();
            textStart = next;
        }

        while (i < source.Length)
        {
            if (source[i] == '{' && i + 1 < source.Length && OpensTag(source[i + 1], dialect))
            {
                FlushText(i);
                var start = i;
                var opener = source[i + 1];
                i += 2;

                if (dialect == TemplateDialect.Jinja && opener == '#')
                {
                    i = SkipPast(source, i, "#}", result, start, "comment");
                    result.Segments.Add(new TemplateSegment(SegmentKind.Comment, source[start..i], start, []));
                    textStart = i;
                    continue;
                }

                if (i < source.Length && (source[i] == '-' || (dialect == TemplateDialect.Jinja && source[i] == '+')))
                    i++;

                if (dialect == TemplateDialect.GoTemplate)
                {
                    var j = i;
                    while (j < source.Length && char.IsWhiteSpace(source[j])) j++;
                    if (j + 1 < source.Length && source[j] == '/' && source[j + 1] == '*')
                    {
                        i = SkipPast(source, j + 2, "*/", result, start, "comment");
                        i = SkipPast(source, i, "}}", result, start, "comment");
                        result.Segments.Add(new TemplateSegment(SegmentKind.Comment, source[start..i], start, []));
                        textStart = i;
                        continue;
                    }
                }

                var closer = opener == '%' ? '%' : '}';
                var tokens = LexTagBody(source, ref i, closer, dialect, result, start);
                var kind = opener == '%' ? SegmentKind.Statement : SegmentKind.Expression;
                var segment = new TemplateSegment(kind, source[start..i], start, tokens);
                result.Segments.Add(segment);
                textStart = i;

                if (kind == SegmentKind.Statement && segment.Keyword == "raw")
                {
                    var end = EndRawRegex().Match(source, i);
                    var rawEnd = end.Success ? end.Index : source.Length;
                    if (!end.Success)
                        result.Errors.Add(new LexError("Unterminated raw block", start));
                    if (rawEnd > i)
                        result.Segments.Add(new TemplateSegment(SegmentKind.Text, source[i..rawEnd], i, []));
                    i = rawEnd;
                    textStart = i;
                }
                continue;
            }

            if (text.Length == 0)
                textStart = i;
            text.Append(source[i]);
            i++;
        }

        FlushText(i);
        return result;
    }

    static bool OpensTag(char next, TemplateDialect dialect) =>
        dialect == TemplateDialect.GoTemplate ? next == '{' : next is '{' or '%' or '#';

    static int SkipPast(string source, int from, string terminator, LexResult result, int start, string what)
    {
        var end = source.IndexOf(terminator, from, StringComparison.Ordinal);
        if (end < 0)
        {
            result.Errors.Add(new LexError($"Unterminated {what}", start));
            return source.Length;
        }
        return end + terminator.Length;
    }

    static List<TemplateToken> LexTagBody(string source, ref int i, char closer, TemplateDialect dialect, LexResult result, int start)
    {
        var tokens = new List<TemplateToken>();
        while (true)
        {
            while (i < source.Length && char.IsWhiteSpace(source[i])) i++;
            if (i >= source.Length)
            {
                result.Errors.Add(new LexError("Unterminated tag", start));
                return tokens;
            }

            var c = source[i];
            if ((c == '-' || c == '+') && i + 2 < source.Length && source[i + 1] == closer && source[i + 2] == '}')
            {
                i += 3;
                return tokens;
            }
            if (c == closer && i + 1 < source.Length && source[i + 1] == '}')
            {
                i += 2;
                return tokens;
            }

            var tokenStart = i;
            if (char.IsLetter(c) || c == '_')
            {
                while (i < source.Length && (char.IsLetterOrDigit(source[i]) || source[i] == '_')) i++;
                tokens.Add(new TemplateToken(TokenKind.Name, source[tokenStart..i], tokenStart));
            }
            else if (char.IsDigit(c))
            {
                while (i < source.Length && (char.IsLetterOrDigit(source[i]) || source[i] == '_' ||
                                             (source[i] == '.' && i + 1 < source.Length && char.IsDigit(source[i + 1]))))
                    i++;
                tokens.Add(new TemplateToken(TokenKind.Number, source[tokenStart..i], tokenStart));
            }
            else if (c is '"' or '\'' || (c == '`' && dialect == TemplateDialect.GoTemplate))
            {
                var value = ReadString(source, ref i, c == '`');
                if (value is null)
                {
                    result.Errors.Add(new LexError("Unterminated string", tokenStart));
                    i = source.Length;
                    return tokens;
                }
                tokens.Add(new TemplateToken(TokenKind.String, value, tokenStart));
            }
            else
            {
                var at = i;
                var op = TwoCharOperators.FirstOrDefault(o => string.CompareOrdinal(source, at, o, 0, 2) == 0) ?? c.ToString();
                i += op.Length;
                tokens.Add(new TemplateToken(TokenKind.Operator, op, tokenStart));
            }
        }
    }

    static string? ReadString(string source, ref int i, bool raw)
    {
        var quote = source[i++];
        var value = new StringBuilder();
        while (i < source.Length)
        {
            var c = source[i++];
            if (c == quote)
                return value.ToString();
            if (c == '\\' && !raw && i < source.Length)
            {
                var e = source[i++];
                value.Append(e switch
                {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    _ => e,
                });
                continue;
            }
            value.Append(c);
        }
        return null;
    }
}
