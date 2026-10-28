using System.Globalization;
using static ModelSafetyCheck.Jinja.Render.JinjaValues;

namespace ModelSafetyCheck.Jinja.Render;

/// <summary>The whitelisted filters, tests and methods. Anything not listed here does not exist for a template.</summary>
static class JinjaFilters
{
    static readonly HashSet<string> StringMethods = ["strip", "lstrip", "rstrip", "split", "rsplit", "startswith", "endswith", "upper", "lower", "replace", "find", "rfind", "count", "title", "capitalize", "splitlines", "join", "isdigit", "isalpha", "isspace", "isupper", "islower", "removeprefix", "removesuffix", "format"];
    static readonly HashSet<string> DictMethods = ["get", "items", "keys", "values"];
    static readonly HashSet<string> ListMethods = ["index", "count"];

    public static bool HasMethod(object target, string name) => target switch
    {
        string => StringMethods.Contains(name),
        JinjaNamespace => false,
        Dictionary<string, object?> => DictMethods.Contains(name),
        List<object?> => ListMethods.Contains(name),
        _ => false,
    };

    static object? Arg(List<object?> args, Dictionary<string, object?> kwargs, int index, string name, object? fallback = null) =>
        index >= 0 && index < args.Count ? args[index] : kwargs.TryGetValue(name, out var v) ? v : fallback;

    public static object? CallMethod(object target, string name, List<object?> a, Dictionary<string, object?> k)
    {
        switch (target)
        {
            case string s:
                switch (name)
                {
                    case "strip": return Arg(a, k, 0, "chars") is string cs ? s.Trim(cs.ToCharArray()) : s.Trim();
                    case "lstrip": return Arg(a, k, 0, "chars") is string ls ? s.TrimStart(ls.ToCharArray()) : s.TrimStart();
                    case "rstrip": return Arg(a, k, 0, "chars") is string rs ? s.TrimEnd(rs.ToCharArray()) : s.TrimEnd();
                    case "split": return Split(s, Arg(a, k, 0, "sep") as string, Arg(a, k, 1, "maxsplit") is long m ? (int)m : -1, fromRight: false);
                    case "rsplit": return Split(s, Arg(a, k, 0, "sep") as string, Arg(a, k, 1, "maxsplit") is long rm ? (int)rm : -1, fromRight: true);
                    case "startswith": return Prefixes(Arg(a, k, 0, "prefix")).Any(p => s.StartsWith(p, StringComparison.Ordinal));
                    case "endswith": return Prefixes(Arg(a, k, 0, "suffix")).Any(p => s.EndsWith(p, StringComparison.Ordinal));
                    case "upper": return s.ToUpperInvariant();
                    case "lower": return s.ToLowerInvariant();
                    case "title": return CultureInfo.InvariantCulture.TextInfo.ToTitleCase(s.ToLowerInvariant());
                    case "capitalize": return s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..].ToLowerInvariant();
                    case "replace": return Replace(s, ToStr(Arg(a, k, 0, "old")), ToStr(Arg(a, k, 1, "new")), Arg(a, k, 2, "count") is long n ? n : -1);
                    case "find": return (long)s.IndexOf(ToStr(Arg(a, k, 0, "sub")), StringComparison.Ordinal);
                    case "rfind": return (long)s.LastIndexOf(ToStr(Arg(a, k, 0, "sub")), StringComparison.Ordinal);
                    case "count": var sub = ToStr(Arg(a, k, 0, "sub")); return sub.Length == 0 ? (long)s.Length + 1 : (long)((s.Length - s.Replace(sub, "").Length) / sub.Length);
                    case "splitlines": return s.Split('\n').Select(l => (object?)l.TrimEnd('\r')).ToList() is var lines && s.EndsWith('\n') ? lines.Take(lines.Count - 1).ToList() : lines;
                    case "join": return string.Join(s, JinjaInterpreter.Iterate(Arg(a, k, 0, "iterable")).Select(ToStr));
                    case "isdigit": return s.Length > 0 && s.All(char.IsDigit);
                    case "isalpha": return s.Length > 0 && s.All(char.IsLetter);
                    case "isspace": return s.Length > 0 && s.All(char.IsWhiteSpace);
                    case "isupper": return s.Any(char.IsLetter) && !s.Any(char.IsLower);
                    case "islower": return s.Any(char.IsLetter) && !s.Any(char.IsUpper);
                    case "format": return Format(s, a, k);
                    case "removeprefix": var pre = ToStr(Arg(a, k, 0, "prefix")); return s.StartsWith(pre, StringComparison.Ordinal) ? s[pre.Length..] : s;
                    case "removesuffix": var suf = ToStr(Arg(a, k, 0, "suffix")); return suf.Length > 0 && s.EndsWith(suf, StringComparison.Ordinal) ? s[..^suf.Length] : s;
                }
                break;
            case Dictionary<string, object?> d:
                switch (name)
                {
                    case "get": return d.TryGetValue(ToStr(Arg(a, k, 0, "key")), out var v) ? v : Arg(a, k, 1, "default");
                    case "items": return d.Select(kv => (object?)new List<object?> { kv.Key, kv.Value }).ToList();
                    case "keys": return d.Keys.Cast<object?>().ToList();
                    case "values": return d.Values.ToList();
                }
                break;
            case List<object?> l:
                switch (name)
                {
                    case "index": var item = Arg(a, k, 0, "value"); return (long)l.FindIndex(x => PyEquals(x, item));
                    case "count": var wanted = Arg(a, k, 0, "value"); return (long)l.Count(x => PyEquals(x, wanted));
                }
                break;
        }
        throw new TemplateRuntimeException($"{TypeName(target)} has no method '{name}'");
    }

    /// <summary>str.format with {}, {0} and {name} fields (format specs are ignored).</summary>
    static string Format(string s, List<object?> a, Dictionary<string, object?> k)
    {
        var b = new System.Text.StringBuilder();
        var auto = 0;
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] == '{' && i + 1 < s.Length && s[i + 1] == '{') { b.Append('{'); i++; continue; }
            if (s[i] == '}' && i + 1 < s.Length && s[i + 1] == '}') { b.Append('}'); i++; continue; }
            if (s[i] != '{') { b.Append(s[i]); continue; }
            var end = s.IndexOf('}', i);
            if (end < 0) throw new TemplateRuntimeException("Unclosed '{' in format string");
            var field = s[(i + 1)..end].Split(':', '!')[0];
            object? value = field.Length == 0 ? (auto < a.Count ? a[auto++] : Undefined.Instance)
                : int.TryParse(field, out var n) ? (n < a.Count ? a[n] : Undefined.Instance)
                : k.TryGetValue(field, out var named) ? named : Undefined.Instance;
            b.Append(ToStr(value));
            i = end;
        }
        return b.ToString();
    }

    static IEnumerable<string> Prefixes(object? value) => value switch
    {
        string s => [s],
        List<object?> list => list.Select(ToStr),
        null or Undefined => [],
        _ => throw new TemplateRuntimeException("startswith/endswith needs a string or tuple"),
    };

    static List<object?> Split(string s, string? sep, int maxSplit, bool fromRight)
    {
        if (sep is null)
        {
            var parts = s.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (maxSplit < 0 || parts.Length <= maxSplit + 1) return parts.Cast<object?>().ToList();
            // Python keeps the remainder as one piece; approximate by re-joining with single spaces.
            return fromRight
                ? new[] { string.Join(' ', parts[..^maxSplit]) }.Concat(parts[^maxSplit..]).Cast<object?>().ToList()
                : parts[..maxSplit].Append(string.Join(' ', parts[maxSplit..])).Cast<object?>().ToList();
        }
        if (sep.Length == 0) throw new TemplateRuntimeException("empty separator");
        if (maxSplit < 0) return s.Split(sep).Cast<object?>().ToList();
        if (!fromRight) return s.Split(sep, maxSplit + 1).Cast<object?>().ToList();
        var result = new List<object?>();
        var rest = s;
        for (var i = 0; i < maxSplit; i++)
        {
            var at = rest.LastIndexOf(sep, StringComparison.Ordinal);
            if (at < 0) break;
            result.Insert(0, rest[(at + sep.Length)..]);
            rest = rest[..at];
        }
        result.Insert(0, rest);
        return result;
    }

    static string Replace(string s, string old, string replacement, long count)
    {
        if (count < 0 || old.Length == 0) return old.Length == 0 ? s : s.Replace(old, replacement, StringComparison.Ordinal);
        var b = new System.Text.StringBuilder();
        var i = 0;
        for (var n = 0; n < count; n++)
        {
            var at = s.IndexOf(old, i, StringComparison.Ordinal);
            if (at < 0) break;
            b.Append(s, i, at - i).Append(replacement);
            i = at + old.Length;
        }
        return b.Append(s, i, s.Length - i).ToString();
    }

    public static object? Apply(JinjaInterpreter it, string name, object? v, List<object?> a, Dictionary<string, object?> k)
    {
        switch (name)
        {
            case "length" or "count": return v switch { string s => (long)s.Length, System.Collections.ICollection c => (long)c.Count, null or Undefined => 0L, _ => throw new TemplateRuntimeException($"{TypeName(v)} has no length") };
            case "trim": return Arg(a, k, 0, "chars") is string chars ? ToStr(v).Trim(chars.ToCharArray()) : ToStr(v).Trim();
            case "upper": return ToStr(v).ToUpperInvariant();
            case "lower": return ToStr(v).ToLowerInvariant();
            case "title": return CallMethod(ToStr(v), "title", [], []);
            case "capitalize": return CallMethod(ToStr(v), "capitalize", [], []);
            case "string": return ToStr(v);
            case "safe": return v;
            case "e" or "escape" or "forceescape": return JinjaInterpreter.HtmlEscape(ToStr(v));
            case "replace": return Replace(ToStr(v), ToStr(Arg(a, k, 0, "old")), ToStr(Arg(a, k, 1, "new")), Arg(a, k, 2, "count") is long n ? n : -1);
            case "default" or "d":
                var boolean = IsTruthy(Arg(a, k, 1, "boolean", false));
                return v is Undefined || (boolean && !IsTruthy(v)) ? Arg(a, k, 0, "default_value", "") : v;
            case "first": return JinjaInterpreter.Iterate(v).FirstOrDefault(Undefined.Instance);
            case "last": return v is string ls ? (ls.Length > 0 ? ls[^1].ToString() : Undefined.Instance) : JinjaInterpreter.Iterate(v).LastOrDefault(Undefined.Instance);
            case "list": return JinjaInterpreter.Iterate(v).ToList();
            case "reverse": return v is string rs ? new string(rs.Reverse().ToArray()) : JinjaInterpreter.Iterate(v).Reverse().ToList();
            case "unique": return Distinct(JinjaInterpreter.Iterate(v));
            case "join":
            {
                var items = JinjaInterpreter.Iterate(v);
                if (Arg(a, k, 1, "attribute") is string attr) items = items.Select(x => JinjaInterpreter.GetAttr(x, attr));
                return string.Join(ToStr(Arg(a, k, 0, "d", "")), items.Select(ToStr));
            }
            case "tojson":
            {
                var indent = Arg(a, k, 0, "indent") is long ind ? (int?)ind : null;
                return ToJson(v, indent, IsTruthy(Arg(a, k, 1, "sort_keys", false)));
            }
            case "items": return v is Dictionary<string, object?> d ? CallMethod(d, "items", [], []) : v is null or Undefined ? new List<object?>() : throw new TemplateRuntimeException("items needs a mapping");
            case "dictsort": return v is Dictionary<string, object?> ds ? ds.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase).Select(kv => (object?)new List<object?> { kv.Key, kv.Value }).ToList() : throw new TemplateRuntimeException("dictsort needs a mapping");
            case "int": return v switch { long l => (object)l, double dbl => (long)dbl, bool b => b ? 1L : 0L, string s when long.TryParse(s.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var p) => p, string s when double.TryParse(s.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var pd) => (long)pd, _ => Arg(a, k, 0, "default", 0L) };
            case "float": return v switch { long l => (double)l, double dbl => dbl, string s when double.TryParse(s.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var p) => p, _ => Arg(a, k, 0, "default", 0.0) };
            case "abs": return v is long al ? (object)Math.Abs(al) : Math.Abs(ToDouble(v));
            case "round": return Math.Round(ToDouble(v), Arg(a, k, 0, "precision") is long pr ? (int)pr : 0, MidpointRounding.ToEven);
            case "sum": return JinjaInterpreter.Iterate(v).Aggregate((object?)0L, (acc, x) => acc is long la && x is long lx ? la + lx : ToDouble(acc) + ToDouble(x));
            case "min": return JinjaInterpreter.Iterate(v).Aggregate((object?)null, (m, x) => m is null || Compare(x, m) < 0 ? x : m) ?? Undefined.Instance;
            case "max": return JinjaInterpreter.Iterate(v).Aggregate((object?)null, (m, x) => m is null || Compare(x, m) > 0 ? x : m) ?? Undefined.Instance;
            case "wordcount": return (long)ToStr(v).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Length;
            case "indent":
            {
                var width = Arg(a, k, 0, "width", 4L) is long w ? new string(' ', (int)w) : ToStr(Arg(a, k, 0, "width"));
                var first = IsTruthy(Arg(a, k, 1, "first", false));
                var blank = IsTruthy(Arg(a, k, 2, "blank", false));
                var lines = ToStr(v).Split('\n');
                return string.Join('\n', lines.Select((l, i) => (i == 0 && !first) || (!blank && l.Trim().Length == 0) ? l : width + l));
            }
            case "sort":
            {
                var reverse = IsTruthy(Arg(a, k, 0, "reverse", false));
                var attribute = Arg(a, k, 2, "attribute") as string;
                var list = JinjaInterpreter.Iterate(v).ToList();
                list.Sort((x, y) => Compare(attribute is null ? x : JinjaInterpreter.GetAttr(x, attribute), attribute is null ? y : JinjaInterpreter.GetAttr(y, attribute)));
                if (reverse) list.Reverse();
                return list;
            }
            case "map":
            {
                var items = JinjaInterpreter.Iterate(v);
                if (Arg(a, k, -1, "attribute") is string attribute)
                    return items.Select(x => JinjaInterpreter.GetAttr(x, attribute) is var r && r is Undefined && k.TryGetValue("default", out var def) ? def : JinjaInterpreter.GetAttr(x, attribute)).ToList();
                var filter = ToStr(Arg(a, k, 0, "name"));
                return items.Select(x => Apply(it, filter, x, a.Skip(1).ToList(), [])).ToList();
            }
            case "select" or "reject":
            {
                var test = a.Count > 0 ? ToStr(a[0]) : null;
                var keep = name == "select";
                return JinjaInterpreter.Iterate(v).Where(x => (test is null ? IsTruthy(x) : Test(test, x, a.Skip(1).ToList())) == keep).ToList();
            }
            case "selectattr" or "rejectattr":
            {
                var attribute = ToStr(Arg(a, k, 0, "attr"));
                var test = a.Count > 1 ? ToStr(a[1]) : null;
                var keep = name == "selectattr";
                return JinjaInterpreter.Iterate(v).Where(x =>
                {
                    var value = JinjaInterpreter.GetAttr(x, attribute) is Undefined && x is Dictionary<string, object?> dx && dx.TryGetValue(attribute, out var raw) ? raw : JinjaInterpreter.GetAttr(x, attribute);
                    return (test is null ? IsTruthy(value) : Test(test, value, a.Skip(2).ToList())) == keep;
                }).ToList();
            }
            case "batch":
            {
                var size = (int)ToDouble(Arg(a, k, 0, "linecount", 1L));
                return JinjaInterpreter.Iterate(v).Chunk(Math.Max(1, size)).Select(c => (object?)c.ToList()).ToList();
            }
            case "center": return ToStr(v);
            case "truncate": var t = ToStr(v); var length = Arg(a, k, 0, "length", 255L) is long tl ? (int)tl : 255; return t.Length <= length ? t : t[..length] + "...";
        }
        throw new TemplateRuntimeException($"Unknown filter '{name}'");
    }

    static List<object?> Distinct(IEnumerable<object?> items)
    {
        var result = new List<object?>();
        foreach (var x in items)
            if (!result.Any(r => PyEquals(r, x))) result.Add(x);
        return result;
    }

    public static bool Test(string name, object? v, List<object?> a) => name switch
    {
        "defined" => v is not Undefined,
        "undefined" => v is Undefined,
        "none" => v is null,
        "string" => v is string,
        "number" => v is long or double,
        "integer" => v is long,
        "float" => v is double,
        "boolean" => v is bool,
        "true" => v is true,
        "false" => v is false,
        "mapping" => v is Dictionary<string, object?>,
        "sequence" => v is List<object?> or string,
        "iterable" => v is List<object?> or string or Dictionary<string, object?>,
        "callable" => v is IJinjaCallable or BoundMethod,
        "even" => v is long e && e % 2 == 0,
        "odd" => v is long o && o % 2 != 0,
        "divisibleby" => v is long dv && a.Count > 0 && a[0] is long by && by != 0 && dv % by == 0,
        "equalto" or "eq" or "==" or "sameas" => a.Count > 0 && PyEquals(v, a[0]),
        "ne" or "!=" => a.Count > 0 && !PyEquals(v, a[0]),
        "gt" or ">" => a.Count > 0 && Compare(v, a[0]) > 0,
        "ge" or ">=" => a.Count > 0 && Compare(v, a[0]) >= 0,
        "lt" or "<" => a.Count > 0 && Compare(v, a[0]) < 0,
        "le" or "<=" => a.Count > 0 && Compare(v, a[0]) <= 0,
        "in" => a.Count > 0 && Contains(a[0], v),
        "lower" => v is string ls && ls == ls.ToLowerInvariant(),
        "upper" => v is string us && us == us.ToUpperInvariant(),
        "search" or "match" => v is string ss && a.Count > 0 && ss.Contains(ToStr(a[0]), StringComparison.Ordinal),
        _ => throw new TemplateRuntimeException($"Unknown test '{name}'"),
    };
}
