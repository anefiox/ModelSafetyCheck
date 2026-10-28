using System.Globalization;
using System.Text;

namespace ModelSafetyCheck.Jinja.Render;

/// <summary>
/// A sandboxed renderer for the Go text/template subset Ollama templates use: fields, variables, pipelines,
/// if / else if / range / with, and the builtin functions (eq, ne, lt, le, gt, ge, and, or, not, len, index,
/// slice, print, printf, json, currentDate). Like the Jinja renderer it only sees plain data and is capped.
/// </summary>
public static class GoTemplateRenderer
{
    public static RenderResult Render(string template, IReadOnlyDictionary<string, object?> data, RenderOptions? options = null)
    {
        options ??= new RenderOptions();
        try
        {
            var nodes = new GoParser(Segments(template)).ParseAll();
            var root = JinjaValues.FromData(data.ToDictionary(kv => kv.Key, kv => kv.Value));
            return new RenderResult(new GoInterpreter(options, root).Render(nodes), null);
        }
        catch (RenderLimitException ex)
        {
            return new RenderResult(null, ex.Message, LimitHit: true);
        }
        catch (Exception ex) when (ex is TemplateSyntaxException or TemplateRuntimeException or InvalidCastException or OverflowException or ArgumentException or FormatException)
        {
            return new RenderResult(null, ex.Message);
        }
    }

    /// <summary>Lexes and applies `{{-` / `-}}` trimming to neighbouring text.</summary>
    static List<TemplateSegment> Segments(string template)
    {
        var lex = TemplateLexer.Lex(template, TemplateDialect.GoTemplate);
        if (lex.Errors.Count > 0)
            throw new TemplateSyntaxException($"{lex.Errors[0].Message} at character {lex.Errors[0].Offset}");
        var segments = lex.Segments;
        var texts = segments.Select(s => s.Kind == SegmentKind.Text ? s.Raw : null).ToArray();
        for (var i = 0; i < segments.Count; i++)
        {
            if (segments[i].Kind == SegmentKind.Text) continue;
            if (segments[i].TrimBefore && i > 0 && texts[i - 1] is { } before) texts[i - 1] = before.TrimEnd();
            if (segments[i].TrimAfter && i + 1 < segments.Count && texts[i + 1] is { } after) texts[i + 1] = after.TrimStart();
        }
        return segments.Select((s, i) => texts[i] is { } t ? s with { Raw = t } : s).ToList();
    }
}

abstract record GoNode;
sealed record GoText(string Text) : GoNode;
sealed record GoAction(GoPipeline Pipeline) : GoNode;
sealed record GoIf(IReadOnlyList<(GoPipeline Test, IReadOnlyList<GoNode> Body)> Branches, IReadOnlyList<GoNode>? Else) : GoNode;
sealed record GoRange(GoPipeline Pipeline, IReadOnlyList<GoNode> Body, IReadOnlyList<GoNode>? Else) : GoNode;
sealed record GoWith(GoPipeline Pipeline, IReadOnlyList<GoNode> Body, IReadOnlyList<GoNode>? Else) : GoNode;
sealed record GoBreak : GoNode;
sealed record GoContinue : GoNode;

/// <summary>`$a, $b := cmd | cmd`. Declare is true for `:=`, false for `=`.</summary>
sealed record GoPipeline(IReadOnlyList<string> Variables, bool Declare, IReadOnlyList<IReadOnlyList<GoOperand>> Commands);

abstract record GoOperand;
sealed record GoLiteral(object? Value) : GoOperand;
sealed record GoFunction(string Name) : GoOperand;
sealed record GoChain(GoOperand? Base, string? Variable, IReadOnlyList<string> Fields) : GoOperand; // .A.B, $x.A, $.A, (pipe).A
sealed record GoSub(GoPipeline Pipeline, IReadOnlyList<string> Fields) : GoOperand;

sealed class GoParser(List<TemplateSegment> segments)
{
    int _pos;
    TemplateSegment? _end;

    public List<GoNode> ParseAll()
    {
        var nodes = ParseBlock(out var end);
        if (end is not null) throw new TemplateSyntaxException($"Unexpected '{end}'");
        return nodes;
    }

    List<GoNode> ParseBlock(out string? end)
    {
        var nodes = new List<GoNode>();
        while (_pos < segments.Count)
        {
            var seg = segments[_pos++];
            if (seg.Kind == SegmentKind.Text) { if (seg.Raw.Length > 0) nodes.Add(new GoText(seg.Raw)); continue; }
            if (seg.Kind == SegmentKind.Comment || seg.Tokens.Count == 0) continue;

            var keyword = seg.Tokens[0].Kind == TokenKind.Name ? seg.Tokens[0].Value : null;
            switch (keyword)
            {
                case "end" or "else":
                    end = keyword;
                    _end = seg;
                    return nodes;
                case "if":
                {
                    var branches = new List<(GoPipeline, IReadOnlyList<GoNode>)>();
                    var test = new GoPipelineParser(seg.Tokens, 1).Parse();
                    List<GoNode>? elseBody = null;
                    while (true)
                    {
                        var body = ParseBlock(out var e);
                        branches.Add((test, body));
                        if (e == "else" && _end!.Tokens.Count > 1 && _end.Tokens[1].Value == "if")
                        {
                            test = new GoPipelineParser(_end.Tokens, 2).Parse();
                            continue;
                        }
                        if (e == "else") elseBody = ParseUntilEnd();
                        else if (e != "end") throw new TemplateSyntaxException("Missing {{end}} for if");
                        break;
                    }
                    nodes.Add(new GoIf(branches, elseBody));
                    break;
                }
                case "range" or "with":
                {
                    var pipeline = new GoPipelineParser(seg.Tokens, 1).Parse();
                    var body = ParseBlock(out var e);
                    var elseBody = e == "else" ? ParseUntilEnd() : e == "end" ? null : throw new TemplateSyntaxException($"Missing {{{{end}}}} for {keyword}");
                    nodes.Add(keyword == "range" ? new GoRange(pipeline, body, elseBody) : new GoWith(pipeline, body, elseBody));
                    break;
                }
                case "break": nodes.Add(new GoBreak()); break;
                case "continue": nodes.Add(new GoContinue()); break;
                case "define" or "template" or "block":
                    throw new TemplateSyntaxException($"Unsupported action '{keyword}'");
                default:
                    nodes.Add(new GoAction(new GoPipelineParser(seg.Tokens, 0).Parse()));
                    break;
            }
        }
        end = null;
        return nodes;
    }

    List<GoNode> ParseUntilEnd()
    {
        var body = ParseBlock(out var e);
        return e == "end" ? body : throw new TemplateSyntaxException("Missing {{end}}");
    }
}

sealed class GoPipelineParser(IReadOnlyList<TemplateToken> tokens, int start)
{
    int _pos = start;

    TemplateToken? Peek(int ahead = 0) => _pos + ahead < tokens.Count ? tokens[_pos + ahead] : null;
    bool Is(string value, int ahead = 0) => Peek(ahead) is { } t && t.Value == value && t.Kind != TokenKind.String;
    static bool Adjacent(TemplateToken a, TemplateToken b) => a.Offset + a.Value.Length == b.Offset;

    public GoPipeline Parse(bool inParens = false)
    {
        var variables = new List<string>();
        var declare = false;
        // Variable declarations: $a := ..., $a, $b := ..., $a = ...
        var save = _pos;
        while (Is("$") && Peek(1) is { Kind: TokenKind.Name } n && Adjacent(Peek()!, n))
        {
            variables.Add(n.Value);
            _pos += 2;
            if (Is(",")) { _pos++; continue; }
            break;
        }
        if (variables.Count > 0 && (Is(":=") || Is("=")))
        {
            declare = Peek()!.Value == ":=";
            _pos++;
        }
        else
        {
            variables.Clear();
            _pos = save;
        }

        var commands = new List<IReadOnlyList<GoOperand>>();
        var command = new List<GoOperand>();
        while (Peek() is { } t)
        {
            if (inParens && Is(")")) break;
            if (Is("|")) { _pos++; commands.Add(command); command = []; continue; }
            command.Add(ParseOperand());
        }
        commands.Add(command);
        if (commands.Any(c => c.Count == 0)) throw new TemplateSyntaxException("Empty command in pipeline");
        return new GoPipeline(variables, declare, commands);
    }

    GoOperand ParseOperand()
    {
        var t = Peek()!;
        _pos++;
        switch (t.Kind)
        {
            case TokenKind.String: return new GoLiteral(t.Value);
            case TokenKind.Number: return new GoLiteral(ParseNumber(t.Value));
            case TokenKind.Name:
                return t.Value switch
                {
                    "true" => new GoLiteral(true),
                    "false" => new GoLiteral(false),
                    "nil" => new GoLiteral(null),
                    _ => new GoFunction(t.Value),
                };
        }

        switch (t.Value)
        {
            case "-" when Peek() is { Kind: TokenKind.Number } num && Adjacent(t, num):
                _pos++;
                return new GoLiteral(ParseNumber(num.Value) switch { long l => (object)(-l), double d => -d, var v => v });
            case ".":
            {
                var fields = new List<string>();
                var previous = t;
                if (Peek() is { Kind: TokenKind.Name } first && Adjacent(t, first)) { fields.Add(first.Value); previous = first; _pos++; }
                fields.AddRange(Fields(ref previous));
                return new GoChain(null, null, fields);
            }
            case "$":
            {
                string variable = "$";
                var previous = t;
                if (Peek() is { Kind: TokenKind.Name } name && Adjacent(t, name)) { variable = name.Value; previous = name; _pos++; }
                return new GoChain(null, variable, Fields(ref previous));
            }
            case "(":
            {
                var pipeline = Parse(inParens: true);
                var close = Peek() ?? throw new TemplateSyntaxException("Missing ')'");
                _pos++;
                return new GoSub(pipeline, Fields(ref close));
            }
        }
        throw new TemplateSyntaxException($"Unexpected '{t.Value}' in action");
    }

    /// <summary>Field accesses glued to the previous token: `.A.B` with no spaces.</summary>
    List<string> Fields(ref TemplateToken previous)
    {
        var fields = new List<string>();
        while (Peek() is { Value: "." } dot && dot.Kind == TokenKind.Operator && Adjacent(previous, dot) && Peek(1) is { Kind: TokenKind.Name } name && Adjacent(dot, name))
        {
            fields.Add(name.Value);
            previous = name;
            _pos += 2;
        }
        return fields;
    }

    static object ParseNumber(string text) =>
        long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var l) ? (object)l
        : double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? (object)d
        : throw new TemplateSyntaxException($"Bad number '{text}'");
}

sealed class GoInterpreter(RenderOptions options, object? root)
{
    readonly StringBuilder _output = new();
    readonly List<Dictionary<string, object?>> _scopes = [new() { ["$"] = root }];
    long _steps;

    sealed class BreakSignal : Exception;
    sealed class ContinueSignal : Exception;

    public string Render(List<GoNode> nodes)
    {
        Exec(nodes, root);
        return _output.ToString();
    }

    void Step()
    {
        if (++_steps > options.MaxSteps) throw new RenderLimitException($"Template exceeded {options.MaxSteps:N0} evaluation steps");
    }

    void Write(string text)
    {
        _output.Append(text);
        if (_output.Length > options.MaxOutputChars) throw new RenderLimitException($"Template output exceeded {options.MaxOutputChars:N0} characters");
    }

    void Exec(IReadOnlyList<GoNode> nodes, object? dot)
    {
        foreach (var node in nodes)
        {
            Step();
            switch (node)
            {
                case GoText t: Write(t.Text); break;
                case GoAction a:
                {
                    var value = EvalPipeline(a.Pipeline, dot);
                    if (a.Pipeline.Variables.Count == 0) Write(Print(value));
                    break;
                }
                case GoIf i:
                {
                    _scopes.Add([]);
                    try
                    {
                        var taken = false;
                        foreach (var (test, body) in i.Branches)
                        {
                            if (!Truthy(EvalPipeline(test, dot))) continue;
                            Exec(body, dot);
                            taken = true;
                            break;
                        }
                        if (!taken && i.Else is not null) Exec(i.Else, dot);
                    }
                    finally { _scopes.RemoveAt(_scopes.Count - 1); }
                    break;
                }
                case GoWith w:
                {
                    _scopes.Add([]);
                    try
                    {
                        var value = EvalPipeline(w.Pipeline, dot);
                        if (Truthy(value)) Exec(w.Body, value);
                        else if (w.Else is not null) Exec(w.Else, dot);
                    }
                    finally { _scopes.RemoveAt(_scopes.Count - 1); }
                    break;
                }
                case GoRange r: ExecRange(r, dot); break;
                case GoBreak: throw new BreakSignal();
                case GoContinue: throw new ContinueSignal();
            }
        }
    }

    void ExecRange(GoRange r, object? dot)
    {
        var scope = new Dictionary<string, object?>();
        _scopes.Add(scope);
        try
        {
            var collection = EvalCommands(r.Pipeline.Commands, dot);
            var items = collection switch
            {
                List<object?> list => list.Select((v, i) => ((object?)(long)i, v)).ToList(),
                Dictionary<string, object?> map => map.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => ((object?)kv.Key, kv.Value)).ToList(),
                long n => Enumerable.Range(0, (int)Math.Clamp(n, 0, 100_000)).Select(i => ((object?)(long)i, (object?)(long)i)).ToList(),
                null => [],
                _ => throw new TemplateRuntimeException($"range can't iterate over {JinjaValues.TypeName(collection)}"),
            };
            if (items.Count == 0)
            {
                if (r.Else is not null) Exec(r.Else, dot);
                return;
            }
            foreach (var (key, value) in items)
            {
                if (r.Pipeline.Variables.Count == 1) scope[r.Pipeline.Variables[0]] = value;
                else if (r.Pipeline.Variables.Count >= 2) { scope[r.Pipeline.Variables[0]] = key; scope[r.Pipeline.Variables[1]] = value; }
                try { Exec(r.Body, value); }
                catch (ContinueSignal) { }
                catch (BreakSignal) { break; }
            }
        }
        finally { _scopes.RemoveAt(_scopes.Count - 1); }
    }

    object? EvalPipeline(GoPipeline p, object? dot)
    {
        var value = EvalCommands(p.Commands, dot);
        foreach (var name in p.Variables)
        {
            if (p.Declare) { _scopes[^1][name] = value; continue; }
            var scope = _scopes.LastOrDefault(s => s.ContainsKey(name)) ?? throw new TemplateRuntimeException($"undefined variable ${name}");
            scope[name] = value;
        }
        return value;
    }

    object? EvalCommands(IReadOnlyList<IReadOnlyList<GoOperand>> commands, object? dot)
    {
        object? piped = null;
        var hasPiped = false;
        foreach (var command in commands)
        {
            piped = EvalCommand(command, dot, hasPiped ? piped : null, hasPiped);
            hasPiped = true;
        }
        return piped;
    }

    object? EvalCommand(IReadOnlyList<GoOperand> command, object? dot, object? piped, bool hasPiped)
    {
        Step();
        if (command[0] is GoFunction f)
        {
            var args = command.Skip(1).Select(o => EvalOperand(o, dot)).ToList();
            if (hasPiped) args.Add(piped);
            return Call(f.Name, command.Skip(1).ToList(), args, dot);
        }
        if (command.Count > 1 || hasPiped)
            throw new TemplateRuntimeException("Only functions can take arguments");
        return EvalOperand(command[0], dot);
    }

    object? EvalOperand(GoOperand operand, object? dot) => operand switch
    {
        GoLiteral l => l.Value,
        GoFunction f => Call(f.Name, [], [], dot),
        GoChain c => Fields(c.Variable is null ? dot : c.Variable == "$" ? root : LookupVariable(c.Variable), c.Fields),
        GoSub s => Fields(EvalPipeline(s.Pipeline, dot), s.Fields),
        _ => throw new TemplateRuntimeException("Unsupported operand"),
    };

    object? LookupVariable(string name)
    {
        for (var i = _scopes.Count - 1; i >= 0; i--)
            if (_scopes[i].TryGetValue(name, out var v)) return v;
        throw new TemplateRuntimeException($"undefined variable ${name}");
    }

    static object? Fields(object? value, IReadOnlyList<string> fields)
    {
        // Data is JSON-shaped (lowercase keys, as Ollama's types serialise); Go templates use field names (.Role).
        foreach (var field in fields)
            value = value is Dictionary<string, object?> map
                ? map.TryGetValue(field, out var exact) ? exact : map.FirstOrDefault(kv => string.Equals(kv.Key, field, StringComparison.OrdinalIgnoreCase)).Value
                : null;
        return value;
    }

    object? Call(string name, List<GoOperand> rawArgs, List<object?> a, object? dot)
    {
        object? Arg(int i) => i < a.Count ? a[i] : throw new TemplateRuntimeException($"{name}: missing argument");
        switch (name)
        {
            case "eq": return a.Skip(1).Any(x => Equal(Arg(0), x));
            case "ne": return !Equal(Arg(0), Arg(1));
            case "lt": return JinjaValues.Compare(Arg(0), Arg(1)) < 0;
            case "le": return JinjaValues.Compare(Arg(0), Arg(1)) <= 0;
            case "gt": return JinjaValues.Compare(Arg(0), Arg(1)) > 0;
            case "ge": return JinjaValues.Compare(Arg(0), Arg(1)) >= 0;
            case "and": foreach (var x in a) if (!Truthy(x)) return x; return a.LastOrDefault();
            case "or": foreach (var x in a) if (Truthy(x)) return x; return a.LastOrDefault();
            case "not": return !Truthy(Arg(0));
            case "len": return Arg(0) switch { string s => (long)s.Length, System.Collections.ICollection c => (long)c.Count, null => 0L, var v => throw new TemplateRuntimeException($"len of {JinjaValues.TypeName(v)}") };
            case "index":
            {
                var v = Arg(0);
                foreach (var key in a.Skip(1))
                    v = v switch { List<object?> l when key is long i => i >= 0 && i < l.Count ? l[(int)i] : throw new TemplateRuntimeException("index out of range"), Dictionary<string, object?> m => m.GetValueOrDefault(JinjaValues.ToStr(key)), _ => null };
                return v;
            }
            case "slice":
            {
                var v = Arg(0);
                var count = v switch { List<object?> l => l.Count, string s => s.Length, _ => throw new TemplateRuntimeException("slice of non-sequence") };
                var from = a.Count > 1 ? (int)JinjaValues.ToDouble(a[1]) : 0;
                var to = a.Count > 2 ? (int)JinjaValues.ToDouble(a[2]) : count;
                if (from < 0 || to > count || from > to) throw new TemplateRuntimeException("slice index out of range");
                return v is string str ? str[from..to] : ((List<object?>)v!).GetRange(from, to - from);
            }
            case "print": return string.Concat(a.Select(Print));
            case "println": return string.Join(" ", a.Select(Print)) + "\n";
            case "printf": return Printf(JinjaValues.ToStr(Arg(0)), a.Skip(1).ToList());
            case "json": return JinjaValues.ToJson(Arg(0)).Replace(", ", ",").Replace(": ", ":");
            case "currentDate": return (options.Now ?? DateTimeOffset.Now).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            case "yesterdayDate": return (options.Now ?? DateTimeOffset.Now).AddDays(-1).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            case "html": return System.Net.WebUtility.HtmlEncode(string.Concat(a.Select(Print)));
            case "urlquery": return Uri.EscapeDataString(string.Concat(a.Select(Print)));
            case "js": return string.Concat(a.Select(Print)).Replace("\\", "\\\\").Replace("'", "\\'").Replace("\"", "\\\"");
            case "toTypeScriptType": return Print(Arg(0));
        }
        throw new TemplateRuntimeException($"function \"{name}\" not defined");
    }

    static bool Equal(object? x, object? y) => JinjaValues.PyEquals(x, y);

    public static bool Truthy(object? v) => v switch
    {
        null => false,
        bool b => b,
        long l => l != 0,
        double d => d != 0,
        string s => s.Length > 0,
        System.Collections.ICollection c => c.Count > 0,
        _ => true,
    };

    /// <summary>Go's default formatting; structured values print as JSON, which is what Ollama's types do.</summary>
    static string Print(object? v) => v switch
    {
        null => "<no value>",
        string s => s,
        bool b => b ? "true" : "false",
        long l => l.ToString(CultureInfo.InvariantCulture),
        double d => d.ToString("G", CultureInfo.InvariantCulture),
        List<object?> or Dictionary<string, object?> => JinjaValues.ToJson(v).Replace(", ", ",").Replace(": ", ":"),
        _ => v.ToString() ?? "",
    };

    static string Printf(string format, List<object?> args)
    {
        var b = new StringBuilder();
        var next = 0;
        for (var i = 0; i < format.Length; i++)
        {
            if (format[i] != '%' || i + 1 >= format.Length) { b.Append(format[i]); continue; }
            var verb = format[++i];
            if (verb == '%') { b.Append('%'); continue; }
            var arg = next < args.Count ? args[next++] : null;
            b.Append(verb == 'q' ? JinjaValues.ToJson(JinjaValues.ToStr(arg)) : Print(arg));
        }
        return b.ToString();
    }
}
