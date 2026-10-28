using System.Globalization;
using System.Text;

namespace ModelSafetyCheck.Jinja.Render;

public sealed class TemplateSyntaxException(string message) : Exception(message);

/// <summary>Builds an AST from lexer segments for the Jinja subset chat templates use.</summary>
sealed class JinjaParser
{
    readonly List<TemplateSegment> _segments;
    int _pos;
    TemplateSegment? _lastEnd;

    JinjaParser(List<TemplateSegment> segments) => _segments = segments;

    public static IReadOnlyList<Node> Parse(string template, bool trimBlocks, bool lstripBlocks)
    {
        // jinja2's default keep_trailing_newline=False drops a single trailing newline from the source.
        if (template.EndsWith("\r\n", StringComparison.Ordinal)) template = template[..^2];
        else if (template.EndsWith('\n')) template = template[..^1];
        var lex = TemplateLexer.Lex(template, TemplateDialect.Jinja);
        if (lex.Errors.Count > 0)
            throw new TemplateSyntaxException($"{lex.Errors[0].Message} at character {lex.Errors[0].Offset}");
        var parser = new JinjaParser(ApplyWhitespaceControl(lex.Segments, trimBlocks, lstripBlocks));
        var body = parser.ParseBlock([], out var end);
        if (end is not null)
            throw new TemplateSyntaxException($"Unexpected '{end}'");
        return body;
    }

    /// <summary>
    /// Applies `-` trimming and, like Hugging Face's apply_chat_template, trim_blocks (drop the newline after a
    /// block tag) and lstrip_blocks (drop indentation before a block tag).
    /// </summary>
    static List<TemplateSegment> ApplyWhitespaceControl(List<TemplateSegment> segments, bool trimBlocks, bool lstripBlocks)
    {
        var texts = segments.Select(s => s.Kind == SegmentKind.Text ? s.Raw : null).ToArray();
        for (var i = 0; i < segments.Count; i++)
        {
            var s = segments[i];
            if (s.Kind == SegmentKind.Text)
                continue;
            var isBlock = s.Kind is SegmentKind.Statement or SegmentKind.Comment;

            if (i > 0 && texts[i - 1] is { } before)
            {
                if (s.TrimBefore)
                    texts[i - 1] = before.TrimEnd();
                else if (lstripBlocks && isBlock && !s.KeepBefore)
                {
                    var lineStart = before.LastIndexOf('\n') + 1;
                    if (before.AsSpan(lineStart).IsWhiteSpace())
                        texts[i - 1] = before[..lineStart];
                }
            }
            if (i + 1 < segments.Count && texts[i + 1] is { } after)
            {
                if (s.TrimAfter)
                    texts[i + 1] = after.TrimStart();
                else if (trimBlocks && isBlock)
                    texts[i + 1] = after.StartsWith("\r\n", StringComparison.Ordinal) ? after[2..] : after.StartsWith('\n') ? after[1..] : after;
            }
        }
        return segments.Select((s, i) => texts[i] is { } t ? s with { Raw = t } : s).ToList();
    }

    List<Node> ParseBlock(HashSet<string> ends, out string? end)
    {
        var nodes = new List<Node>();
        while (_pos < _segments.Count)
        {
            var seg = _segments[_pos++];
            switch (seg.Kind)
            {
                case SegmentKind.Text:
                    if (seg.Raw.Length > 0) nodes.Add(new TextNode(seg.Raw));
                    continue;
                case SegmentKind.Comment:
                    continue;
                case SegmentKind.Expression:
                    nodes.Add(new OutputNode(ExprParser.ParseAll(seg.Tokens, 0)));
                    continue;
            }

            var keyword = seg.Keyword ?? throw new TemplateSyntaxException("Empty block tag");
            if (ends.Contains(keyword))
            {
                end = keyword;
                _lastEnd = seg;
                return nodes;
            }
            nodes.AddRange(ParseStatement(keyword, seg));
        }
        end = null;
        if (ends.Count > 0)
            throw new TemplateSyntaxException($"Missing {string.Join(" or ", ends.Select(e => $"'{e}'"))}");
        return nodes;
    }

    IEnumerable<Node> ParseStatement(string keyword, TemplateSegment seg)
    {
        var t = seg.Tokens;
        switch (keyword)
        {
            case "if":
            {
                var branches = new List<(Expr, IReadOnlyList<Node>)>();
                var test = ExprParser.ParseAll(t, 1);
                List<Node>? elseBody = null;
                while (true)
                {
                    var body = ParseBlock(["elif", "else", "endif"], out var end);
                    branches.Add((test, body));
                    if (end == "elif") { test = ExprParser.ParseAll(_lastEnd!.Tokens, 1); continue; }
                    if (end == "else") elseBody = ParseBlock(["endif"], out _);
                    break;
                }
                yield return new IfNode(branches, elseBody);
                break;
            }
            case "for":
            {
                var inIndex = t.FindIndex(x => x.Kind == TokenKind.Name && x.Value == "in");
                if (inIndex < 2) throw new TemplateSyntaxException("Malformed for loop");
                var targets = t.Take(inIndex).Skip(1).Where(x => x.Kind == TokenKind.Name).Select(x => x.Value).ToList();
                var p = new ExprParser(t, inIndex + 1, allowCondExpr: false);
                var iterable = p.ParseTuple();
                Expr? filter = null;
                if (p.AcceptName("if")) filter = p.ParseExpression(allowCond: false);
                p.AcceptName("recursive");
                p.ExpectEnd();
                var body = ParseBlock(["else", "endfor"], out var end);
                var elseBody = end == "else" ? ParseBlock(["endfor"], out _) : null;
                yield return new ForNode(targets, iterable, filter, body, elseBody);
                break;
            }
            case "set":
            {
                var eq = t.FindIndex(x => x.Kind == TokenKind.Operator && x.Value == "=");
                if (eq < 0)
                {
                    var name = t.Count > 1 ? t[1].Value : throw new TemplateSyntaxException("Malformed set");
                    yield return new SetBlockNode(name, ParseBlock(["endset"], out _));
                    break;
                }
                var targetParser = new ExprParser(t.Take(eq).ToList(), 1, allowCondExpr: false);
                var targets = new List<Expr> { targetParser.ParsePrimaryWithPostfix() };
                while (targetParser.AcceptOp(",")) targets.Add(targetParser.ParsePrimaryWithPostfix());
                yield return new SetNode(targets, ExprParser.ParseAll(t, eq + 1, tuple: true));
                break;
            }
            case "macro":
            {
                var p = new ExprParser(t, 1, allowCondExpr: true);
                var name = p.ExpectName();
                var parameters = new List<(string, Expr?)>();
                p.ExpectOp("(");
                while (!p.AcceptOp(")"))
                {
                    var param = p.ExpectName();
                    parameters.Add((param, p.AcceptOp("=") ? p.ParseExpression() : null));
                    p.AcceptOp(",");
                }
                yield return new MacroNode(name, parameters, ParseBlock(["endmacro"], out _));
                break;
            }
            case "generation": // Hugging Face marker for assistant spans; renders its body.
                foreach (var node in ParseBlock(["endgeneration"], out _)) yield return node;
                break;
            case "filter":
            {
                var p = new ExprParser(t, 1);
                var name = p.ExpectName();
                var args = new List<Expr>();
                if (p.AcceptOp("("))
                    while (!p.AcceptOp(")")) { args.Add(p.ParseExpression()); p.AcceptOp(","); }
                yield return new FilterBlockNode(name, args, ParseBlock(["endfilter"], out _));
                break;
            }
            case "break":
                yield return new BreakNode();
                break;
            case "continue":
                yield return new ContinueNode();
                break;
            case "raw" or "endraw":
                break;
            default:
                throw new TemplateSyntaxException($"Unsupported tag '{keyword}'");
        }
    }
}

/// <summary>Recursive-descent expression parser following Jinja's precedence.</summary>
sealed class ExprParser(IReadOnlyList<TemplateToken> tokens, int start, bool allowCondExpr = true)
{
    int _pos = start;

    public static Expr ParseAll(IReadOnlyList<TemplateToken> tokens, int start, bool tuple = false)
    {
        var p = new ExprParser(tokens, start);
        var e = tuple ? p.ParseTuple() : p.ParseExpression();
        p.ExpectEnd();
        return e;
    }

    TemplateToken? Peek(int ahead = 0) => _pos + ahead < tokens.Count ? tokens[_pos + ahead] : null;
    bool IsOp(string op, int ahead = 0) => Peek(ahead) is { Kind: TokenKind.Operator } t && t.Value == op;
    bool IsName(string name, int ahead = 0) => Peek(ahead) is { Kind: TokenKind.Name } t && t.Value == name;

    public bool AcceptOp(string op) { if (!IsOp(op)) return false; _pos++; return true; }
    public bool AcceptName(string name) { if (!IsName(name)) return false; _pos++; return true; }
    public void ExpectOp(string op) { if (!AcceptOp(op)) throw Error($"expected '{op}'"); }
    public string ExpectName() => Peek() is { Kind: TokenKind.Name } t ? tokens[_pos++].Value : throw Error("expected a name");
    public void ExpectEnd() { if (_pos < tokens.Count) throw Error($"unexpected '{tokens[_pos].Value}'"); }

    TemplateSyntaxException Error(string message) => new($"Expression: {message}{(Peek() is { } t ? $" near '{t.Value}'" : " at end")}");

    /// <summary>`a, b` without brackets is a tuple (list) in `set` and `for`.</summary>
    public Expr ParseTuple()
    {
        var first = ParseExpression(allowCondExpr);
        if (!IsOp(",")) return first;
        var items = new List<Expr> { first };
        while (AcceptOp(",") && Peek() is not null && !IsName("if"))
            items.Add(ParseExpression(allowCondExpr));
        return new ListExpr(items);
    }

    public Expr ParseExpression(bool allowCond = true)
    {
        var e = ParseOr();
        if (allowCond && IsName("if"))
        {
            _pos++;
            var test = ParseOr();
            Expr? otherwise = AcceptName("else") ? ParseExpression() : null;
            return new CondExpr(test, e, otherwise);
        }
        return e;
    }

    Expr ParseOr()
    {
        var e = ParseAnd();
        while (AcceptName("or")) e = new BinaryExpr("or", e, ParseAnd());
        return e;
    }

    Expr ParseAnd()
    {
        var e = ParseNot();
        while (AcceptName("and")) e = new BinaryExpr("and", e, ParseNot());
        return e;
    }

    Expr ParseNot() => AcceptName("not") ? new UnaryExpr("not", ParseNot()) : ParseCompare();

    Expr ParseCompare()
    {
        var e = ParseConcat();
        while (true)
        {
            if (Peek() is { Kind: TokenKind.Operator } op && op.Value is "==" or "!=" or "<" or ">" or "<=" or ">=")
            {
                _pos++;
                e = new BinaryExpr(op.Value, e, ParseConcat());
            }
            else if (AcceptName("in"))
                e = new BinaryExpr("in", e, ParseConcat());
            else if (IsName("not") && IsName("in", 1))
            {
                _pos += 2;
                e = new BinaryExpr("not in", e, ParseConcat());
            }
            else
                return e;
        }
    }

    Expr ParseConcat()
    {
        var e = ParseAdd();
        while (AcceptOp("~")) e = new BinaryExpr("~", e, ParseAdd());
        return e;
    }

    Expr ParseAdd()
    {
        var e = ParseMul();
        while (Peek() is { Kind: TokenKind.Operator } op && op.Value is "+" or "-")
        {
            _pos++;
            e = new BinaryExpr(op.Value, e, ParseMul());
        }
        return e;
    }

    Expr ParseMul()
    {
        var e = ParsePow();
        while (Peek() is { Kind: TokenKind.Operator } op && op.Value is "*" or "/" or "//" or "%")
        {
            _pos++;
            e = new BinaryExpr(op.Value, e, ParsePow());
        }
        return e;
    }

    Expr ParsePow()
    {
        var e = ParseUnary();
        while (AcceptOp("**")) e = new BinaryExpr("**", e, ParseUnary());
        return e;
    }

    Expr ParseUnary()
    {
        if (AcceptOp("-")) return new UnaryExpr("-", ParseUnary());
        if (AcceptOp("+")) return ParseUnary();
        return ParseFiltersAndTests(ParsePrimaryWithPostfix());
    }

    Expr ParseFiltersAndTests(Expr e)
    {
        while (true)
        {
            if (AcceptOp("|"))
            {
                var name = ExpectName();
                var (args, kwargs) = IsOp("(") ? ParseCallArgs() : ([], []);
                e = new FilterExpr(e, name, args, kwargs);
            }
            else if (AcceptName("is"))
            {
                var negated = AcceptName("not");
                var name = Peek() is { } t && t.Kind is TokenKind.Name or TokenKind.Operator ? tokens[_pos++].Value : throw Error("expected a test");
                var args = new List<Expr>();
                if (IsOp("("))
                    args.AddRange(ParseCallArgs().Args);
                else if (IsOp("["))
                    args.Add(ParsePrimaryWithPostfix());
                else if (Peek() is { Kind: TokenKind.String or TokenKind.Number } || (Peek() is { Kind: TokenKind.Name } n && n.Value is not ("and" or "or" or "if" or "else" or "in" or "not" or "is")))
                    args.Add(ParsePrimaryWithPostfix());
                e = new TestExpr(e, name, args, negated);
            }
            else
                return e;
        }
    }

    public Expr ParsePrimaryWithPostfix()
    {
        var e = ParsePrimary();
        while (true)
        {
            if (AcceptOp("."))
            {
                var t = Peek() ?? throw Error("expected an attribute");
                _pos++;
                e = t.Kind == TokenKind.Number ? new ItemExpr(e, new LiteralExpr(long.Parse(t.Value, CultureInfo.InvariantCulture))) : new AttrExpr(e, t.Value);
            }
            else if (AcceptOp("["))
                e = ParseSubscript(e);
            else if (IsOp("("))
            {
                var (args, kwargs) = ParseCallArgs();
                e = new CallExpr(e, args, kwargs);
            }
            else
                return e;
        }
    }

    Expr ParseSubscript(Expr target)
    {
        Expr? first = IsOp(":") ? null : ParseExpression();
        if (AcceptOp("]")) return new ItemExpr(target, first!);
        ExpectOp(":");
        Expr? stop = IsOp(":") || IsOp("]") ? null : ParseExpression();
        Expr? step = null;
        if (AcceptOp(":") && !IsOp("]")) step = ParseExpression();
        ExpectOp("]");
        return new SliceExpr(target, first, stop, step);
    }

    (List<Expr> Args, List<(string, Expr)> Kwargs) ParseCallArgs()
    {
        ExpectOp("(");
        var args = new List<Expr>();
        var kwargs = new List<(string, Expr)>();
        while (!AcceptOp(")"))
        {
            if (Peek() is { Kind: TokenKind.Name } n && IsOp("=", 1))
            {
                _pos += 2;
                kwargs.Add((n.Value, ParseExpression()));
            }
            else
                args.Add(ParseExpression());
            if (!AcceptOp(",") && !IsOp(")")) throw Error("expected ',' or ')'");
        }
        return (args, kwargs);
    }

    Expr ParsePrimary()
    {
        var t = Peek() ?? throw Error("unexpected end of expression");
        _pos++;
        switch (t.Kind)
        {
            case TokenKind.String:
            {
                var text = new StringBuilder(t.Value);
                while (Peek() is { Kind: TokenKind.String } next) { text.Append(next.Value); _pos++; }
                return new LiteralExpr(text.ToString());
            }
            case TokenKind.Number:
            {
                var v = t.Value.Replace("_", "");
                if (long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var l)) return new LiteralExpr(l);
                if (double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out var d)) return new LiteralExpr(d);
                throw Error("bad number");
            }
            case TokenKind.Name:
                return t.Value switch
                {
                    "true" or "True" => new LiteralExpr(true),
                    "false" or "False" => new LiteralExpr(false),
                    "none" or "None" => new LiteralExpr(null),
                    _ => new NameExpr(t.Value),
                };
        }

        switch (t.Value)
        {
            case "(":
            {
                if (AcceptOp(")")) return new ListExpr([]);
                var e = ParseExpression();
                if (AcceptOp(")")) return e;
                var items = new List<Expr> { e };
                while (AcceptOp(",") && !IsOp(")")) items.Add(ParseExpression());
                ExpectOp(")");
                return new ListExpr(items);
            }
            case "[":
            {
                var items = new List<Expr>();
                while (!AcceptOp("]"))
                {
                    items.Add(ParseExpression());
                    if (!AcceptOp(",") && !IsOp("]")) throw Error("expected ',' or ']'");
                }
                return new ListExpr(items);
            }
            case "{":
            {
                var items = new List<(Expr, Expr)>();
                while (!AcceptOp("}"))
                {
                    var key = ParseExpression();
                    ExpectOp(":");
                    items.Add((key, ParseExpression()));
                    if (!AcceptOp(",") && !IsOp("}")) throw Error("expected ',' or '}'");
                }
                return new DictExpr(items);
            }
        }
        _pos--;
        throw Error("unexpected token");
    }
}

static class ListExtensions
{
    public static int FindIndex(this IReadOnlyList<TemplateToken> list, Func<TemplateToken, bool> match)
    {
        for (var i = 0; i < list.Count; i++)
            if (match(list[i])) return i;
        return -1;
    }
}
