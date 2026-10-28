using System.Globalization;
using System.Text;

namespace ModelSafetyCheck.Jinja.Render;

/// <summary>Jinja's Undefined: prints as empty, is falsy, and (leniently) yields Undefined for any attribute.</summary>
public sealed class Undefined
{
    public static readonly Undefined Instance = new();
    Undefined() { }
    public override string ToString() => "";
}

/// <summary>`namespace(...)`: the only object whose attributes templates may assign.</summary>
public sealed class JinjaNamespace : Dictionary<string, object?>;

public sealed class TemplateRuntimeException(string message) : Exception(message);

/// <summary>Raised by the template's own `raise_exception(...)`.</summary>
public sealed class TemplateRaisedException(string message) : Exception(message);

interface IJinjaCallable
{
    object? Invoke(JinjaInterpreter interpreter, List<object?> args, Dictionary<string, object?> kwargs);
}

sealed class BuiltinFunction(string name, Func<JinjaInterpreter, List<object?>, Dictionary<string, object?>, object?> body) : IJinjaCallable
{
    public string Name { get; } = name;
    public object? Invoke(JinjaInterpreter interpreter, List<object?> args, Dictionary<string, object?> kwargs) => body(interpreter, args, kwargs);
}

sealed record BoundMethod(object Target, string Name);

/// <summary>Python-like semantics for the values a chat template sees: None, bool, long, double, string, list, dict.</summary>
static class JinjaValues
{
    public static bool IsTruthy(object? v) => v switch
    {
        null or Undefined => false,
        bool b => b,
        long l => l != 0,
        double d => d != 0,
        string s => s.Length > 0,
        System.Collections.ICollection c => c.Count > 0,
        _ => true,
    };

    public static bool IsNumber(object? v) => v is long or double or bool;

    public static double ToDouble(object? v) => v switch
    {
        long l => l,
        double d => d,
        bool b => b ? 1 : 0,
        _ => throw new TemplateRuntimeException($"Expected a number, got {TypeName(v)}"),
    };

    public static string TypeName(object? v) => v switch
    {
        null => "None",
        Undefined => "undefined",
        bool => "bool",
        long => "int",
        double => "float",
        string => "str",
        List<object?> => "list",
        JinjaNamespace => "namespace",
        Dictionary<string, object?> => "dict",
        _ => v.GetType().Name,
    };

    /// <summary>str(): how Jinja prints a value.</summary>
    public static string ToStr(object? v) => v switch
    {
        string s => s,
        Undefined => "",
        _ => Repr(v),
    };

    /// <summary>Python repr(), used when lists and dicts are printed.</summary>
    public static string Repr(object? v) => v switch
    {
        null => "None",
        Undefined => "",
        bool b => b ? "True" : "False",
        long l => l.ToString(CultureInfo.InvariantCulture),
        double d => FormatDouble(d),
        string s => ReprString(s),
        List<object?> list => "[" + string.Join(", ", list.Select(Repr)) + "]",
        Dictionary<string, object?> dict => "{" + string.Join(", ", dict.Select(kv => $"{ReprString(kv.Key)}: {Repr(kv.Value)}")) + "}",
        _ => v.ToString() ?? "",
    };

    public static string FormatDouble(double d)
    {
        if (double.IsNaN(d)) return "nan";
        if (double.IsInfinity(d)) return d > 0 ? "inf" : "-inf";
        if (d == Math.Floor(d) && Math.Abs(d) < 1e16) return d.ToString("0.0", CultureInfo.InvariantCulture);
        return d.ToString("R", CultureInfo.InvariantCulture);
    }

    static string ReprString(string s)
    {
        var quote = s.Contains('\'') && !s.Contains('"') ? '"' : '\'';
        var b = new StringBuilder().Append(quote);
        foreach (var c in s)
        {
            b.Append(c switch
            {
                '\\' => "\\\\",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                _ when c == quote => "\\" + c,
                _ => c.ToString(),
            });
        }
        return b.Append(quote).ToString();
    }

    public static bool PyEquals(object? a, object? b)
    {
        if (a is Undefined || b is Undefined) return a is Undefined && b is Undefined;
        if (IsNumber(a) && IsNumber(b)) return ToDouble(a) == ToDouble(b);
        return (a, b) switch
        {
            (null, null) => true,
            (string x, string y) => x == y,
            (List<object?> x, List<object?> y) => x.Count == y.Count && x.Zip(y).All(p => PyEquals(p.First, p.Second)),
            (Dictionary<string, object?> x, Dictionary<string, object?> y) => x.Count == y.Count && x.All(kv => y.TryGetValue(kv.Key, out var o) && PyEquals(kv.Value, o)),
            _ => ReferenceEquals(a, b),
        };
    }

    public static int Compare(object? a, object? b)
    {
        if (IsNumber(a) && IsNumber(b)) return ToDouble(a).CompareTo(ToDouble(b));
        if (a is string x && b is string y) return string.CompareOrdinal(x, y);
        if (a is List<object?> la && b is List<object?> lb)
        {
            for (var i = 0; i < Math.Min(la.Count, lb.Count); i++)
            {
                var c = Compare(la[i], lb[i]);
                if (c != 0) return c;
            }
            return la.Count.CompareTo(lb.Count);
        }
        throw new TemplateRuntimeException($"Cannot compare {TypeName(a)} with {TypeName(b)}");
    }

    public static bool Contains(object? container, object? item) => container switch
    {
        string s => item is string sub ? s.Contains(sub, StringComparison.Ordinal) : throw new TemplateRuntimeException("'in <string>' requires a string"),
        List<object?> list => list.Any(x => PyEquals(x, item)),
        Dictionary<string, object?> dict => item is string key && dict.ContainsKey(key),
        null or Undefined => false,
        _ => throw new TemplateRuntimeException($"Argument of type {TypeName(container)} is not iterable"),
    };

    /// <summary>Python json.dumps as used by Hugging Face's tojson filter (ensure_ascii=False).</summary>
    public static string ToJson(object? v, int? indent = null, bool sortKeys = false)
    {
        var b = new StringBuilder();
        WriteJson(b, v, indent, 0, sortKeys);
        return b.ToString();
    }

    static void WriteJson(StringBuilder b, object? v, int? indent, int depth, bool sortKeys)
    {
        var itemSeparator = indent is null ? ", " : ",";
        void NewLine(int level) { if (indent is { } n) b.Append('\n').Append(' ', n * level); }

        switch (v)
        {
            case null or Undefined: b.Append("null"); break;
            case bool x: b.Append(x ? "true" : "false"); break;
            case long l: b.Append(l.ToString(CultureInfo.InvariantCulture)); break;
            case double d: b.Append(double.IsNaN(d) ? "NaN" : double.IsInfinity(d) ? (d > 0 ? "Infinity" : "-Infinity") : FormatDouble(d)); break;
            case string s: WriteJsonString(b, s); break;
            case List<object?> list:
                if (list.Count == 0) { b.Append("[]"); break; }
                b.Append('[');
                for (var i = 0; i < list.Count; i++)
                {
                    if (i > 0) b.Append(itemSeparator);
                    NewLine(depth + 1);
                    WriteJson(b, list[i], indent, depth + 1, sortKeys);
                }
                NewLine(depth);
                b.Append(']');
                break;
            case Dictionary<string, object?> dict:
                if (dict.Count == 0) { b.Append("{}"); break; }
                b.Append('{');
                var first = true;
                foreach (var (key, value) in sortKeys ? dict.OrderBy(kv => kv.Key, StringComparer.Ordinal) : dict.AsEnumerable())
                {
                    if (!first) b.Append(itemSeparator);
                    first = false;
                    NewLine(depth + 1);
                    WriteJsonString(b, key);
                    b.Append(": ");
                    WriteJson(b, value, indent, depth + 1, sortKeys);
                }
                NewLine(depth);
                b.Append('}');
                break;
            default: WriteJsonString(b, v.ToString() ?? ""); break;
        }
    }

    static void WriteJsonString(StringBuilder b, string s)
    {
        b.Append('"');
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': b.Append("\\\""); break;
                case '\\': b.Append("\\\\"); break;
                case '\n': b.Append("\\n"); break;
                case '\r': b.Append("\\r"); break;
                case '\t': b.Append("\\t"); break;
                case '\b': b.Append("\\b"); break;
                case '\f': b.Append("\\f"); break;
                default:
                    if (c < 0x20) b.Append($"\\u{(int)c:x4}");
                    else b.Append(c);
                    break;
            }
        }
        b.Append('"');
    }

    /// <summary>Converts plain .NET data (from callers) into template values.</summary>
    public static object? FromData(object? v) => v switch
    {
        null => null,
        string or bool or long or double or Undefined => v,
        int i => (long)i,
        float f => (double)f,
        IDictionary<string, object?> dict => dict.ToDictionary(kv => kv.Key, kv => FromData(kv.Value)),
        System.Collections.IEnumerable list => list.Cast<object?>().Select(FromData).ToList(),
        _ => v.ToString(),
    };
}
