using System.Text.Json;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Cli;

/// <summary>
/// `modelcheck explain`: renders a chat template in the sandbox and prints exactly what the model receives,
/// plus every trigger probe that changed the output.
/// </summary>
static class ExplainCommand
{
    sealed record Source(string Name, string Template, string Bos, string Eos);

    public static int Run(string path, string? messagesFile, TextWriter output)
    {
        List<Source> sources;
        try
        {
            sources = Load(path);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException or InvalidOperationException)
        {
            output.WriteLine($"Could not read {path}: {ex.Message}");
            return Program.ExitError;
        }
        if (sources.Count == 0)
        {
            output.WriteLine($"No Jinja chat template found in {path}. (Ollama's Go templates can't be rendered yet; use `modelcheck local --dump-template`.)");
            return Program.ExitError;
        }

        List<Dictionary<string, object?>>? messages = null;
        if (messagesFile is not null)
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(messagesFile));
            messages = doc.RootElement.EnumerateArray().Select(m => m.EnumerateObject().ToDictionary(p => p.Name, p => ToValue(p.Value))).ToList();
        }

        var worst = Severity.Info;
        foreach (var source in sources)
        {
            var explanation = TemplateExplainer.Explain(source.Template, new ExplainOptions { BosToken = source.Bos, EosToken = source.Eos, Messages = messages });
            output.WriteLine($"==> {source.Name}");
            if (explanation.Error is not null)
            {
                output.WriteLine($"    Could not render: {explanation.Error}");
                continue;
            }
            foreach (var note in explanation.Notes)
                output.WriteLine($"    Note: {note}");

            Block(output, messages is null ? "Prompt for the sample conversation" : "Prompt for your conversation", explanation.Prompt!);
            if (explanation.PromptWithTools is { } withTools)
                Block(output, "Prompt when one tool (get_weather) is available", withTools);

            if (explanation.ProbesRun == 0)
                output.WriteLine("    No trigger candidates: the template does not compare messages against phrases or dates.");
            else if (explanation.Probes.Count == 0)
                output.WriteLine($"    Ran {explanation.ProbesRun} trigger probe(s); none changed the prompt.");
            else
            {
                output.WriteLine($"    {explanation.Probes.Count} of {explanation.ProbesRun} trigger probe(s) changed the prompt:");
                foreach (var finding in TemplateExplainer.Findings(explanation, source.Name))
                {
                    worst = finding.Severity > worst ? finding.Severity : worst;
                    output.WriteLine($"    [{finding.Severity.ToString().ToUpperInvariant()}] {finding.Title}");
                    foreach (var line in finding.Detail.Split('\n').Skip(1))
                        output.WriteLine($"       {line}");
                }
            }
            output.WriteLine();
        }
        return worst >= Severity.High ? Program.ExitHighRisk : Program.ExitClean;
    }

    static void Block(TextWriter output, string title, string text)
    {
        output.WriteLine($"    ---- {title} ({text.Length:N0} chars) ----");
        output.WriteLine(text);
        output.WriteLine("    ---- end ----");
    }

    static List<Source> Load(string path)
    {
        if (path.EndsWith(".gguf", StringComparison.OrdinalIgnoreCase))
        {
            var file = GgufParser.Parse(path);
            var tokens = file.GetArray("tokenizer.ggml.tokens")?.Strings;
            string Token(string key, string fallback) =>
                file.GetInteger(key) is { } id && tokens is not null && id >= 0 && id < tokens.Count ? tokens[(int)id] : fallback;
            var bos = Token("tokenizer.ggml.bos_token_id", "<s>");
            var eos = Token("tokenizer.ggml.eos_token_id", "</s>");
            return file.Metadata.Where(kv => TemplateRules.IsTemplateKey(kv.Key) && kv.Value is string)
                .Select(kv => new Source($"{path} ({kv.Key})", (string)kv.Value!, bos, eos)).ToList();
        }

        var text = File.ReadAllText(path);
        if (path.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            using var doc = JsonDocument.Parse(text);
            var root = doc.RootElement;
            string Special(string name, string fallback) => root.TryGetProperty(name, out var t)
                ? t.ValueKind == JsonValueKind.String ? t.GetString()! : t.ValueKind == JsonValueKind.Object && t.TryGetProperty("content", out var c) ? c.GetString() ?? fallback : fallback
                : fallback;
            var bos = Special("bos_token", "<s>");
            var eos = Special("eos_token", "</s>");
            if (!root.TryGetProperty("chat_template", out var template))
                return [];
            return template.ValueKind == JsonValueKind.String
                ? [new Source($"{path} (chat_template)", template.GetString()!, bos, eos)]
                : template.EnumerateArray().Select(t => new Source($"{path} (chat_template.{t.GetProperty("name").GetString()})", t.GetProperty("template").GetString()!, bos, eos)).ToList();
        }
        return [new Source(path, text, "<s>", "</s>")];
    }

    static object? ToValue(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Number => e.TryGetInt64(out var l) ? l : e.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Array => e.EnumerateArray().Select(ToValue).ToList(),
        JsonValueKind.Object => e.EnumerateObject().ToDictionary(p => p.Name, p => ToValue(p.Value)),
        _ => null,
    };
}
