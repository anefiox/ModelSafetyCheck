using System.Globalization;
using System.Net;
using System.Text;
using static ModelSafetyCheck.Jinja.Render.JinjaValues;

namespace ModelSafetyCheck.Jinja.Render;

public sealed class RenderLimitException(string message) : Exception(message);

/// <summary>
/// Evaluates a parsed template. It has no reflection, file, network or process access: templates can only
/// read the data passed in and call the whitelisted functions, filters and methods below. Names starting
/// with "__" are always undefined, and steps, output size and recursion depth are capped.
/// </summary>
sealed class JinjaInterpreter
{
    readonly RenderOptions _options;
    readonly List<Dictionary<string, object?>> _frames = [];
    StringBuilder _output = new();
    long _steps;
    int _depth;

    sealed class BreakSignal : Exception;
    sealed class ContinueSignal : Exception;

    public JinjaInterpreter(RenderOptions options, IReadOnlyDictionary<string, object?> context)
    {
        _options = options;
        var globals = new Dictionary<string, object?>
        {
            ["range"] = new BuiltinFunction("range", (_, a, _) => Range(a)),
            ["namespace"] = new BuiltinFunction("namespace", (_, a, k) => Namespace(a, k)),
            ["dict"] = new BuiltinFunction("dict", (_, a, k) => Dict(a, k)),
            ["raise_exception"] = new BuiltinFunction("raise_exception", (_, a, _) => throw new TemplateRaisedException(a.Count > 0 ? ToStr(a[0]) : "")),
            ["strftime_now"] = new BuiltinFunction("strftime_now", (_, a, _) => Strftime(options.Now ?? DateTimeOffset.Now, a.Count > 0 ? ToStr(a[0]) : "%Y-%m-%d")),
        };
        foreach (var (key, value) in context)
            globals[key] = FromData(value);
        _frames.Add(globals);
    }

    public string Render(IReadOnlyList<Node> nodes)
    {
        Exec(nodes);
        return _output.ToString();
    }

    void Step()
    {
        if (++_steps > _options.MaxSteps)
            throw new RenderLimitException($"Template exceeded {_options.MaxSteps:N0} evaluation steps (possible resource exhaustion)");
    }

    void Write(string text)
    {
        _output.Append(text);
        if (_output.Length > _options.MaxOutputChars)
            throw new RenderLimitException($"Template output exceeded {_options.MaxOutputChars:N0} characters");
    }

    // ---------- statements ----------

    void Exec(IReadOnlyList<Node> nodes)
    {
        foreach (var node in nodes)
        {
            Step();
            switch (node)
            {
                case TextNode t: Write(t.Text); break;
                case OutputNode o: Write(ToStr(Eval(o.Value))); break;
                case IfNode i:
                {
                    var taken = false;
                    foreach (var (test, body) in i.Branches)
                    {
                        if (!IsTruthy(Eval(test))) continue;
                        Exec(body);
                        taken = true;
                        break;
                    }
                    if (!taken && i.Else is not null) Exec(i.Else);
                    break;
                }
                case ForNode f: ExecFor(f); break;
                case SetNode s: ExecSet(s); break;
                case SetBlockNode sb:
                {
                    var saved = _output;
                    _output = new StringBuilder();
                    try { Exec(sb.Body); _frames[^1][sb.Name] = _output.ToString(); }
                    finally { _output = saved; }
                    break;
                }
                case FilterBlockNode fb:
                {
                    var saved = _output;
                    _output = new StringBuilder();
                    string body;
                    try { Exec(fb.Body); body = _output.ToString(); }
                    finally { _output = saved; }
                    Write(ToStr(JinjaFilters.Apply(this, fb.Name, body, fb.Args.Select(Eval).ToList(), [])));
                    break;
                }
                case MacroNode m: _frames[^1][m.Name] = new Macro(m, this); break;
                case BreakNode: throw new BreakSignal();
                case ContinueNode: throw new ContinueSignal();
            }
        }
    }

    void ExecFor(ForNode f)
    {
        var items = Iterate(Eval(f.Iterable)).ToList();
        var frame = new Dictionary<string, object?>();
        _frames.Add(frame);
        try
        {
            if (f.Filter is not null)
                items = items.Where(item => { Assign(frame, f.Targets, item); return IsTruthy(Eval(f.Filter)); }).ToList();
            if (items.Count == 0)
            {
                _frames.RemoveAt(_frames.Count - 1);
                frame = null;
                if (f.Else is not null) Exec(f.Else);
                return;
            }

            for (var i = 0; i < items.Count; i++)
            {
                // Like jinja2, `set` inside the body lasts for one iteration only (namespaces are how state crosses iterations).
                frame.Clear();
                Assign(frame, f.Targets, items[i]);
                var index = i;
                frame["loop"] = new Dictionary<string, object?>
                {
                    ["index"] = (long)i + 1, ["index0"] = (long)i, ["first"] = i == 0, ["last"] = i == items.Count - 1,
                    ["length"] = (long)items.Count, ["revindex"] = (long)(items.Count - i), ["revindex0"] = (long)(items.Count - i - 1),
                    ["previtem"] = i > 0 ? items[i - 1] : Undefined.Instance, ["nextitem"] = i + 1 < items.Count ? items[i + 1] : Undefined.Instance,
                    ["cycle"] = new BuiltinFunction("cycle", (_, a, _) => a.Count == 0 ? null : a[index % a.Count]),
                };
                try { Exec(f.Body); }
                catch (ContinueSignal) { }
                catch (BreakSignal) { break; }
            }
        }
        finally
        {
            if (frame is not null) _frames.RemoveAt(_frames.Count - 1);
        }
    }

    static void Assign(Dictionary<string, object?> frame, IReadOnlyList<string> targets, object? item)
    {
        if (targets.Count == 1) { frame[targets[0]] = item; return; }
        var values = item as List<object?> ?? throw new TemplateRuntimeException("Cannot unpack a non-sequence in for");
        for (var t = 0; t < targets.Count; t++)
            frame[targets[t]] = t < values.Count ? values[t] : Undefined.Instance;
    }

    void ExecSet(SetNode s)
    {
        var value = Eval(s.Value);
        if (s.Targets.Count > 1)
        {
            var values = value as List<object?> ?? throw new TemplateRuntimeException("Cannot unpack value in set");
            for (var i = 0; i < s.Targets.Count; i++) SetTarget(s.Targets[i], i < values.Count ? values[i] : Undefined.Instance);
        }
        else
            SetTarget(s.Targets[0], value);
    }

    void SetTarget(Expr target, object? value)
    {
        switch (target)
        {
            case NameExpr n: _frames[^1][n.Name] = value; break;
            case AttrExpr { Target: var t, Name: var name } when Eval(t) is JinjaNamespace ns: ns[name] = value; break;
            default: throw new TemplateRuntimeException("Only names and namespace attributes can be assigned");
        }
    }

    // ---------- expressions ----------

    public object? Eval(Expr expr)
    {
        Step();
        switch (expr)
        {
            case LiteralExpr l: return l.Value;
            case NameExpr n: return Lookup(n.Name);
            case AttrExpr a: return GetAttr(Eval(a.Target), a.Name);
            case ItemExpr i: return GetItem(Eval(i.Target), Eval(i.Index));
            case SliceExpr s: return Slice(Eval(s.Target), s.Start is null ? null : Eval(s.Start), s.Stop is null ? null : Eval(s.Stop), s.Step is null ? null : Eval(s.Step));
            case ListExpr l: return l.Items.Select(Eval).ToList();
            case DictExpr d:
            {
                var dict = new Dictionary<string, object?>();
                foreach (var (k, v) in d.Items) dict[ToStr(Eval(k))] = Eval(v);
                return dict;
            }
            case CondExpr c: return IsTruthy(Eval(c.Test)) ? Eval(c.Then) : c.Else is null ? Undefined.Instance : Eval(c.Else);
            case UnaryExpr { Op: "not" } u: return !IsTruthy(Eval(u.Operand));
            case UnaryExpr { Op: "-" } u: return Eval(u.Operand) switch { long l => (object)(-l), var v => -ToDouble(v) };
            case BinaryExpr b: return EvalBinary(b);
            case CallExpr call:
            {
                var args = call.Args.Select(Eval).ToList();
                var kwargs = call.Kwargs.ToDictionary(k => k.Name, k => Eval(k.Value));
                var function = Eval(call.Function);
                if (function is Undefined)
                    throw new TemplateRuntimeException($"'{Describe(call.Function)}' is undefined and cannot be called");
                return Call(function, args, kwargs);
            }
            case FilterExpr f: return JinjaFilters.Apply(this, f.Name, Eval(f.Value), f.Args.Select(Eval).ToList(), f.Kwargs.ToDictionary(k => k.Name, k => Eval(k.Value)));
            case TestExpr t:
            {
                var result = JinjaFilters.Test(t.Name, Eval(t.Value), t.Args.Select(Eval).ToList());
                return t.Negated ? !result : result;
            }
        }
        throw new TemplateRuntimeException($"Unsupported expression {expr.GetType().Name}");
    }

    static string Describe(Expr e) => e switch
    {
        NameExpr n => n.Name,
        AttrExpr a => $"{Describe(a.Target)}.{a.Name}",
        ItemExpr i => $"{Describe(i.Target)}[...]",
        CallExpr c => $"{Describe(c.Function)}(...)",
        _ => "expression",
    };

    object? Lookup(string name)
    {
        if (name.StartsWith("__", StringComparison.Ordinal)) return Undefined.Instance;
        for (var i = _frames.Count - 1; i >= 0; i--)
            if (_frames[i].TryGetValue(name, out var v)) return v;
        return Undefined.Instance;
    }

    object? EvalBinary(BinaryExpr b)
    {
        if (b.Op == "and") { var l = Eval(b.Left); return IsTruthy(l) ? Eval(b.Right) : l; }
        if (b.Op == "or") { var l = Eval(b.Left); return IsTruthy(l) ? l : Eval(b.Right); }

        var left = Eval(b.Left);
        var right = Eval(b.Right);
        switch (b.Op)
        {
            case "==": return PyEquals(left, right);
            case "!=": return !PyEquals(left, right);
            case "<": return Compare(left, right) < 0;
            case ">": return Compare(left, right) > 0;
            case "<=": return Compare(left, right) <= 0;
            case ">=": return Compare(left, right) >= 0;
            case "in": return Contains(right, left);
            case "not in": return !Contains(right, left);
            case "~": return ToStr(left) + ToStr(right);
            case "+":
                return (left, right) switch
                {
                    (string x, string y) => x + y,
                    (string x, Undefined) => x,
                    (Undefined, string y) => y,
                    (List<object?> x, List<object?> y) => x.Concat(y).ToList(),
                    (long x, long y) => x + y,
                    _ when IsNumber(left) && IsNumber(right) => ToDouble(left) + ToDouble(right),
                    _ => throw new TemplateRuntimeException($"Cannot add {TypeName(left)} and {TypeName(right)}"),
                };
            case "-": return left is long a && right is long c ? (object)(a - c) : ToDouble(left) - ToDouble(right);
            case "*":
                if (left is string s && right is long n) return Repeat(s, n);
                if (left is List<object?> list && right is long times) return Enumerable.Repeat(list, (int)Math.Clamp(times, 0, 10_000)).SelectMany(x => x).ToList();
                return left is long m && right is long k ? (object)(m * k) : ToDouble(left) * ToDouble(right);
            case "/": return ToDouble(left) / ToDouble(right);
            case "//": return left is long q && right is long r ? (object)(long)Math.Floor((double)q / r) : Math.Floor(ToDouble(left) / ToDouble(right));
            case "%":
                if (left is string) throw new TemplateRuntimeException("String % formatting is not supported");
                return left is long x1 && right is long y1 ? (object)(((x1 % y1) + y1) % y1) : ToDouble(left) % ToDouble(right);
            case "**":
                var power = Math.Pow(ToDouble(left), ToDouble(right));
                return left is long && right is long e && e >= 0 && Math.Abs(power) < long.MaxValue ? (object)(long)power : power;
        }
        throw new TemplateRuntimeException($"Unknown operator {b.Op}");
    }

    string Repeat(string s, long n)
    {
        if ((long)s.Length * n > _options.MaxOutputChars) throw new RenderLimitException("String repetition too large");
        return string.Concat(Enumerable.Repeat(s, (int)Math.Max(0, n)));
    }

    public object? Call(object? function, List<object?> args, Dictionary<string, object?> kwargs) => function switch
    {
        IJinjaCallable c => c.Invoke(this, args, kwargs),
        BoundMethod m => JinjaFilters.CallMethod(m.Target, m.Name, args, kwargs),
        _ => throw new TemplateRuntimeException($"{TypeName(function)} is not callable"),
    };

    public static object? GetAttr(object? target, string name)
    {
        // Values are plain data, so there is no object model to escape into; dunders are refused anyway so that
        // sandbox-escape probes evaluate to nothing. Template variables like `_sc` are ordinary names.
        if (name.StartsWith("__", StringComparison.Ordinal)) return Undefined.Instance;
        if (target is Dictionary<string, object?> dict)
        {
            if (dict.TryGetValue(name, out var v)) return v;
            return target is JinjaNamespace ? Undefined.Instance : JinjaFilters.HasMethod(target, name) ? new BoundMethod(target, name) : Undefined.Instance;
        }
        if (target is string or List<object?> && JinjaFilters.HasMethod(target, name)) return new BoundMethod(target!, name);
        return Undefined.Instance;
    }

    public static object? GetItem(object? target, object? index)
    {
        switch (target)
        {
            case Dictionary<string, object?> dict:
                var key = ToStr(index);
                if (key.StartsWith("__", StringComparison.Ordinal)) return Undefined.Instance;
                return dict.TryGetValue(key, out var v) ? v : Undefined.Instance;
            case List<object?> list when index is long i:
                if (i < 0) i += list.Count;
                return i >= 0 && i < list.Count ? list[(int)i] : Undefined.Instance;
            case string s when index is long j:
                if (j < 0) j += s.Length;
                return j >= 0 && j < s.Length ? s[(int)j].ToString() : Undefined.Instance;
            case string s when index is string name:
                return GetAttr(s, name);
            default:
                return Undefined.Instance;
        }
    }

    static object? Slice(object? target, object? start, object? stop, object? step)
    {
        if (target is null or Undefined) return Undefined.Instance;
        var count = target switch { string s => s.Length, List<object?> l => l.Count, _ => throw new TemplateRuntimeException($"Cannot slice {TypeName(target)}") };
        var st = step is long sv ? sv : 1;
        if (st == 0) throw new TemplateRuntimeException("Slice step cannot be zero");

        long Norm(object? v, long fallback)
        {
            if (v is not long x) return fallback;
            if (x < 0) x += count;
            return st > 0 ? Math.Clamp(x, 0, count) : Math.Clamp(x, -1, count - 1);
        }
        var from = Norm(start, st > 0 ? 0 : count - 1);
        var to = Norm(stop, st > 0 ? count : -1);
        var indexes = new List<int>();
        for (var i = from; st > 0 ? i < to : i > to; i += st) indexes.Add((int)i);
        return target is string str ? string.Concat(indexes.Select(i => str[i])) : indexes.Select(i => ((List<object?>)target!)[i]).ToList();
    }

    public static IEnumerable<object?> Iterate(object? value) => value switch
    {
        null or Undefined => [],
        List<object?> list => list,
        Dictionary<string, object?> dict => dict.Keys.Cast<object?>(),
        string s => s.Select(c => (object?)c.ToString()),
        _ => throw new TemplateRuntimeException($"{TypeName(value)} is not iterable"),
    };

    static List<object?> Range(List<object?> a)
    {
        long start = 0, stop, step = 1;
        if (a.Count == 1) stop = (long)ToDouble(a[0]);
        else if (a.Count >= 2) { start = (long)ToDouble(a[0]); stop = (long)ToDouble(a[1]); if (a.Count > 2) step = (long)ToDouble(a[2]); }
        else throw new TemplateRuntimeException("range() needs arguments");
        if (step == 0) throw new TemplateRuntimeException("range() step cannot be zero");
        var count = Math.Max(0, (stop - start + step + (step > 0 ? -1 : 1)) / step);
        if (count > 100_000) throw new RenderLimitException($"range() of {count:N0} items (possible resource exhaustion)");
        var result = new List<object?>();
        for (var i = start; step > 0 ? i < stop : i > stop; i += step) result.Add(i);
        return result;
    }

    /// <summary>Python dict(): copies a mapping or a list of pairs, then applies keyword arguments.</summary>
    static Dictionary<string, object?> Dict(List<object?> args, Dictionary<string, object?> kwargs)
    {
        var result = new Dictionary<string, object?>();
        if (args.Count > 0)
        {
            switch (args[0])
            {
                case Dictionary<string, object?> source:
                    foreach (var (k, v) in source) result[k] = v;
                    break;
                case List<object?> pairs:
                    foreach (var pair in pairs)
                        if (pair is List<object?> { Count: 2 } kv) result[ToStr(kv[0])] = kv[1];
                        else throw new TemplateRuntimeException("dict() needs pairs");
                    break;
                case null or Undefined:
                    break;
                default:
                    throw new TemplateRuntimeException($"dict() cannot convert {TypeName(args[0])}");
            }
        }
        foreach (var (k, v) in kwargs) result[k] = v;
        return result;
    }

    static JinjaNamespace Namespace(List<object?> args, Dictionary<string, object?> kwargs)
    {
        var ns = new JinjaNamespace();
        if (args.Count > 0 && args[0] is Dictionary<string, object?> initial)
            foreach (var (k, v) in initial) ns[k] = v;
        foreach (var (k, v) in kwargs) ns[k] = v;
        return ns;
    }

    static string Strftime(DateTimeOffset now, string format)
    {
        var b = new StringBuilder();
        for (var i = 0; i < format.Length; i++)
        {
            if (format[i] != '%' || i + 1 >= format.Length) { b.Append(format[i]); continue; }
            var c = format[++i];
            b.Append(c switch
            {
                'Y' => now.Year.ToString("0000", CultureInfo.InvariantCulture),
                'y' => (now.Year % 100).ToString("00", CultureInfo.InvariantCulture),
                'm' => now.Month.ToString("00", CultureInfo.InvariantCulture),
                'd' => now.Day.ToString("00", CultureInfo.InvariantCulture),
                'e' => now.Day.ToString(CultureInfo.InvariantCulture).PadLeft(2),
                'H' => now.Hour.ToString("00", CultureInfo.InvariantCulture),
                'I' => ((now.Hour + 11) % 12 + 1).ToString("00", CultureInfo.InvariantCulture),
                'M' => now.Minute.ToString("00", CultureInfo.InvariantCulture),
                'S' => now.Second.ToString("00", CultureInfo.InvariantCulture),
                'p' => now.Hour < 12 ? "AM" : "PM",
                'b' => now.ToString("MMM", CultureInfo.InvariantCulture),
                'B' => now.ToString("MMMM", CultureInfo.InvariantCulture),
                'a' => now.ToString("ddd", CultureInfo.InvariantCulture),
                'A' => now.ToString("dddd", CultureInfo.InvariantCulture),
                'j' => now.DayOfYear.ToString("000", CultureInfo.InvariantCulture),
                '%' => "%",
                _ => "%" + c,
            });
        }
        return b.ToString();
    }

    sealed class Macro(MacroNode node, JinjaInterpreter owner) : IJinjaCallable
    {
        public object? Invoke(JinjaInterpreter interpreter, List<object?> args, Dictionary<string, object?> kwargs)
        {
            if (++owner._depth > 64) throw new RenderLimitException("Macro recursion too deep");
            var frame = new Dictionary<string, object?>();
            for (var i = 0; i < node.Parameters.Count; i++)
            {
                var (name, def) = node.Parameters[i];
                frame[name] = i < args.Count ? args[i] : kwargs.TryGetValue(name, out var kv) ? kv : def is null ? Undefined.Instance : owner.Eval(def);
            }
            frame["varargs"] = args.Skip(node.Parameters.Count).ToList();
            frame["kwargs"] = kwargs.Where(k => node.Parameters.All(p => p.Name != k.Key)).ToDictionary(k => k.Key, k => k.Value);

            // Macros see globals and their own arguments, not the caller's locals.
            var savedFrames = owner._frames.ToList();
            var savedOutput = owner._output;
            owner._frames.RemoveRange(1, owner._frames.Count - 1);
            owner._frames.Add(frame);
            owner._output = new StringBuilder();
            try
            {
                owner.Exec(node.Body);
                return owner._output.ToString();
            }
            finally
            {
                owner._frames.Clear();
                owner._frames.AddRange(savedFrames);
                owner._output = savedOutput;
                owner._depth--;
            }
        }
    }

    public static string HtmlEscape(string s) => WebUtility.HtmlEncode(s);
}
