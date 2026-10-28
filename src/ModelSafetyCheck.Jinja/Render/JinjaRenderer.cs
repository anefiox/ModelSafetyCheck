namespace ModelSafetyCheck.Jinja.Render;

public sealed record RenderOptions
{
    public long MaxSteps { get; init; } = 2_000_000;
    public int MaxOutputChars { get; init; } = 2_000_000;

    /// <summary>The clock seen by `strftime_now`; set it to test date-dependent templates.</summary>
    public DateTimeOffset? Now { get; init; }

    /// <summary>Hugging Face's apply_chat_template uses trim_blocks and lstrip_blocks.</summary>
    public bool TrimBlocks { get; init; } = true;
    public bool LstripBlocks { get; init; } = true;
}

/// <summary>Output, or the reason rendering stopped. <see cref="Raised"/> is true when the template called raise_exception.</summary>
public sealed record RenderResult(string? Output, string? Error, bool Raised = false, bool LimitHit = false)
{
    public bool Success => Output is not null;
}

/// <summary>
/// A sandboxed Jinja renderer for chat templates. Unlike Python's jinja2 it is not a general object model:
/// the template only sees plain data (strings, numbers, lists, dicts) plus whitelisted helpers, so the
/// sandbox-escape tricks behind CVE-2024-34359 have nothing to reach.
/// </summary>
public static class JinjaRenderer
{
    public static RenderResult Render(string template, IReadOnlyDictionary<string, object?> context, RenderOptions? options = null)
    {
        options ??= new RenderOptions();
        try
        {
            var nodes = JinjaParser.Parse(template, options.TrimBlocks, options.LstripBlocks);
            return new RenderResult(new JinjaInterpreter(options, context).Render(nodes), null);
        }
        catch (TemplateRaisedException ex)
        {
            return new RenderResult(null, $"The template raised an error: {ex.Message}", Raised: true);
        }
        catch (RenderLimitException ex)
        {
            return new RenderResult(null, ex.Message, LimitHit: true);
        }
        catch (Exception ex) when (ex is TemplateSyntaxException or TemplateRuntimeException or InvalidCastException or OverflowException or ArgumentException or InvalidOperationException or FormatException)
        {
            return new RenderResult(null, ex.Message);
        }
    }
}
