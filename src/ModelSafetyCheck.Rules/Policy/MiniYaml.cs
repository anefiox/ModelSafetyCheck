using System.Globalization;
using System.Text;

namespace ModelSafetyCheck.Rules.Policy;

public sealed class PolicyException(string message) : Exception(message);

/// <summary>
/// A parser for the small YAML subset a policy file needs: block mappings and sequences (by indentation),
/// sequences of mappings, plain / single-quoted / double-quoted scalars, flow sequences (<c>[a, b]</c>) and
/// <c>#</c> comments. It produces <see cref="Dictionary{TKey,TValue}"/>, <see cref="List{T}"/> and string nodes.
/// Anchors, tags, multi-document streams and block scalars are rejected rather than half-supported, and no
/// reflection is used, so it stays Native-AOT safe.
/// </summary>
public static class MiniYaml
{
    sealed record Line(int Number, int Indent, string Text);

    public static object? Parse(string yaml)
    {
        var lines = new List<Line>();
        var number = 0;
        foreach (var raw in yaml.Replace("\r\n", "\n").Split('\n'))
        {
            number++;
            if (raw.Contains('\t') && raw.TrimStart().Length > 0 && raw[..(raw.Length - raw.TrimStart().Length)].Contains('\t'))
                throw new PolicyException($"Line {number}: tabs are not allowed for indentation.");
            var text = StripComment(raw).TrimEnd();
            if (text.Trim().Length == 0) continue;
            if (text.Trim() is "---" or "...") continue;
            lines.Add(new Line(number, text.Length - text.TrimStart().Length, text.Trim()));
        }
        if (lines.Count == 0) return null;
        var pos = 0;
        var result = ParseBlock(lines, ref pos, lines[0].Indent);
        if (pos < lines.Count)
            throw new PolicyException($"Line {lines[pos].Number}: unexpected indentation.");
        return result;
    }

    static object? ParseBlock(List<Line> lines, ref int pos, int indent)
    {
        var first = lines[pos];
        if (first.Indent != indent)
            throw new PolicyException($"Line {first.Number}: unexpected indentation.");
        return first.Text.StartsWith("- ", StringComparison.Ordinal) || first.Text == "-"
            ? ParseSequence(lines, ref pos, indent)
            : ParseMapping(lines, ref pos, indent);
    }

    static List<object?> ParseSequence(List<Line> lines, ref int pos, int indent)
    {
        var items = new List<object?>();
        while (pos < lines.Count && lines[pos].Indent == indent && (lines[pos].Text.StartsWith("- ", StringComparison.Ordinal) || lines[pos].Text == "-"))
        {
            var line = lines[pos];
            var rest = line.Text.Length > 1 ? line.Text[2..].TrimStart() : "";
            if (rest.Length == 0)
            {
                pos++;
                items.Add(pos < lines.Count && lines[pos].Indent > indent ? ParseBlock(lines, ref pos, lines[pos].Indent) : null);
                continue;
            }
            if (IsMappingEntry(rest))
            {
                // "- key: value" starts a mapping whose further keys are indented to the column after "- ".
                var itemIndent = indent + (line.Text.Length - rest.Length);
                lines[pos] = line with { Indent = itemIndent, Text = rest };
                items.Add(ParseMapping(lines, ref pos, itemIndent));
                continue;
            }
            items.Add(ParseScalarOrFlow(rest, line.Number));
            pos++;
        }
        return items;
    }

    static Dictionary<string, object?> ParseMapping(List<Line> lines, ref int pos, int indent)
    {
        var map = new Dictionary<string, object?>(StringComparer.Ordinal);
        while (pos < lines.Count && lines[pos].Indent == indent)
        {
            var line = lines[pos];
            if (!IsMappingEntry(line.Text))
                throw new PolicyException($"Line {line.Number}: expected 'key: value'.");
            var colon = KeyEnd(line.Text);
            var key = Unquote(line.Text[..colon].Trim(), line.Number) ?? throw new PolicyException($"Line {line.Number}: a key cannot be null.");
            var value = line.Text[(colon + 1)..].Trim();
            if (map.ContainsKey(key))
                throw new PolicyException($"Line {line.Number}: duplicate key '{key}'.");
            pos++;
            if (value.Length > 0)
                map[key] = ParseScalarOrFlow(value, line.Number);
            else if (pos < lines.Count && lines[pos].Indent > indent)
                map[key] = ParseBlock(lines, ref pos, lines[pos].Indent);
            else if (pos < lines.Count && lines[pos].Indent == indent && lines[pos].Text.StartsWith("- ", StringComparison.Ordinal))
                map[key] = ParseSequence(lines, ref pos, indent); // a sequence may sit at the key's own indentation
            else
                map[key] = null;
        }
        if (pos < lines.Count && lines[pos].Indent > indent)
            throw new PolicyException($"Line {lines[pos].Number}: unexpected indentation.");
        return map;
    }

    static bool IsMappingEntry(string text) => !text.StartsWith('[') && KeyEnd(text) > 0;

    /// <summary>Index of the ':' that ends a key ("key:" or "key: value"), outside quotes; -1 if none.</summary>
    static int KeyEnd(string text)
    {
        char? quote = null;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (quote is not null) { if (c == quote) quote = null; continue; }
            if (c is '"' or '\'' && i == 0) { quote = c; continue; }
            if (c == ':' && (i + 1 == text.Length || text[i + 1] == ' ')) return i;
        }
        return -1;
    }

    static object? ParseScalarOrFlow(string value, int line)
    {
        if (value.StartsWith('&') || value.StartsWith('*') || value.StartsWith('!') || value is "|" or ">" || value.StartsWith("|-") || value.StartsWith(">-"))
            throw new PolicyException($"Line {line}: anchors, tags and block scalars are not supported.");
        if (value.StartsWith('{'))
            throw new PolicyException($"Line {line}: flow mappings ({{...}}) are not supported; use indented 'key: value' lines.");
        if (!value.StartsWith('['))
            return Unquote(value, line);
        if (!value.EndsWith(']'))
            throw new PolicyException($"Line {line}: unterminated '['.");
        var items = new List<object?>();
        var inner = value[1..^1];
        var current = new StringBuilder();
        char? quote = null;
        foreach (var c in inner)
        {
            if (quote is not null) { current.Append(c); if (c == quote) quote = null; continue; }
            if (c is '"' or '\'') { quote = c; current.Append(c); continue; }
            if (c == ',') { Add(); continue; }
            current.Append(c);
        }
        if (current.ToString().Trim().Length > 0 || items.Count > 0) Add();
        return items;

        void Add()
        {
            var item = current.ToString().Trim();
            if (item.Length == 0) throw new PolicyException($"Line {line}: empty item in '[...]'.");
            items.Add(Unquote(item, line));
            current.Clear();
        }
    }

    static string? Unquote(string value, int line)
    {
        if (value is "~" or "null" or "Null" or "NULL") return null;
        if (value.Length >= 2 && value[0] == '\'' && value[^1] == '\'')
            return value[1..^1].Replace("''", "'");
        if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
        {
            var b = new StringBuilder();
            for (var i = 1; i < value.Length - 1; i++)
            {
                if (value[i] != '\\' || i + 1 >= value.Length - 1) { b.Append(value[i]); continue; }
                var e = value[++i];
                b.Append(e switch { 'n' => '\n', 't' => '\t', '"' => '"', '\\' => '\\', _ => throw new PolicyException($"Line {line}: unsupported escape '\\{e}'.") });
            }
            return b.ToString();
        }
        if (value.StartsWith('"') || value.StartsWith('\''))
            throw new PolicyException($"Line {line}: unterminated quoted string.");
        return value;
    }

    static string StripComment(string line)
    {
        char? quote = null;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quote is not null) { if (c == quote) quote = null; continue; }
            if (c is '"' or '\'') { quote = c; continue; }
            if (c == '#' && (i == 0 || char.IsWhiteSpace(line[i - 1]))) return line[..i];
        }
        return line;
    }

    /// <summary>Converts a JSON document to the same node shapes, so .json policies share the binder.</summary>
    public static object? FromJson(System.Text.Json.JsonElement e) => e.ValueKind switch
    {
        System.Text.Json.JsonValueKind.Object => e.EnumerateObject().ToDictionary(p => p.Name, p => FromJson(p.Value), StringComparer.Ordinal),
        System.Text.Json.JsonValueKind.Array => e.EnumerateArray().Select(FromJson).ToList(),
        System.Text.Json.JsonValueKind.String => e.GetString(),
        System.Text.Json.JsonValueKind.Number => e.GetRawText(),
        System.Text.Json.JsonValueKind.True => "true",
        System.Text.Json.JsonValueKind.False => "false",
        _ => null,
    };

    internal static string Invariant(this DateOnly d) => d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
}
