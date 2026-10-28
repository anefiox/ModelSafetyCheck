namespace ModelSafetyCheck.Jinja.Render;

// Statement nodes.
abstract record Node;
sealed record TextNode(string Text) : Node;
sealed record OutputNode(Expr Value) : Node;
sealed record IfNode(IReadOnlyList<(Expr Test, IReadOnlyList<Node> Body)> Branches, IReadOnlyList<Node>? Else) : Node;
sealed record ForNode(IReadOnlyList<string> Targets, Expr Iterable, Expr? Filter, IReadOnlyList<Node> Body, IReadOnlyList<Node>? Else) : Node;
sealed record SetNode(IReadOnlyList<Expr> Targets, Expr Value) : Node;
sealed record SetBlockNode(string Name, IReadOnlyList<Node> Body) : Node;
sealed record MacroNode(string Name, IReadOnlyList<(string Name, Expr? Default)> Parameters, IReadOnlyList<Node> Body) : Node;
sealed record FilterBlockNode(string Name, IReadOnlyList<Expr> Args, IReadOnlyList<Node> Body) : Node;
sealed record BreakNode : Node;
sealed record ContinueNode : Node;

// Expression nodes.
abstract record Expr;
sealed record LiteralExpr(object? Value) : Expr;
sealed record NameExpr(string Name) : Expr;
sealed record AttrExpr(Expr Target, string Name) : Expr;
sealed record ItemExpr(Expr Target, Expr Index) : Expr;
sealed record SliceExpr(Expr Target, Expr? Start, Expr? Stop, Expr? Step) : Expr;
sealed record CallExpr(Expr Function, IReadOnlyList<Expr> Args, IReadOnlyList<(string Name, Expr Value)> Kwargs) : Expr;
sealed record FilterExpr(Expr Value, string Name, IReadOnlyList<Expr> Args, IReadOnlyList<(string Name, Expr Value)> Kwargs) : Expr;
sealed record TestExpr(Expr Value, string Name, IReadOnlyList<Expr> Args, bool Negated) : Expr;
sealed record BinaryExpr(string Op, Expr Left, Expr Right) : Expr;
sealed record UnaryExpr(string Op, Expr Operand) : Expr;
sealed record CondExpr(Expr Test, Expr Then, Expr? Else) : Expr;
sealed record ListExpr(IReadOnlyList<Expr> Items) : Expr;
sealed record DictExpr(IReadOnlyList<(Expr Key, Expr Value)> Items) : Expr;
