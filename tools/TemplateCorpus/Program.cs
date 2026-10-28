// False-positive benchmark: analyses the chat templates of the most-downloaded GGUF repos on Hugging Face
// (as parsed by the Hub, so no model files are downloaded) and reports how often each rule fires.
// Usage: dotnet run --project tools/TemplateCorpus -- [count=1000] [--show RULE]
// Malicious templates are rare in the wild, so nearly every warning here is a false positive to tune away.

using System.Text.Json;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Jinja;
using ModelSafetyCheck.Rules;

var count = args.FirstOrDefault(a => int.TryParse(a, out _)) is { } n ? int.Parse(n) : 1000;
var show = args.SkipWhile(a => a != "--show").Skip(1).FirstOrDefault();
if (args.Contains("--classifier"))
    TextClassification.Classifier = ModelSafetyCheck.Classifier.PromptInjectionClassifier.Load(ModelSafetyCheck.Classifier.PromptInjectionClassifier.DefaultDirectory);
var dump = args.SkipWhile(a => a != "--dump").Skip(1).FirstOrDefault();       // write {repo: template} for render_reference.py
var compare = args.SkipWhile(a => a != "--compare").Skip(1).FirstOrDefault(); // compare with its jinja2 output

using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
http.DefaultRequestHeaders.UserAgent.ParseAdd("modelcheck-corpus/1.0");

var repos = new List<(string Id, long Downloads, string Template)>();
string? url = $"https://huggingface.co/api/models?filter=gguf&sort=downloads&direction=-1&limit={Math.Min(count, 1000)}&expand[]=gguf&expand[]=downloads";
while (url is not null && repos.Count < count)
{
    using var response = await http.GetAsync(url);
    response.EnsureSuccessStatusCode();
    using (var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        foreach (var m in doc.RootElement.EnumerateArray())
            if (m.TryGetProperty("gguf", out var g) && g.TryGetProperty("chat_template", out var t) && t.GetString() is { Length: > 0 } template)
                repos.Add((m.GetProperty("id").GetString()!, m.TryGetProperty("downloads", out var d) ? d.GetInt64() : 0, template));
    url = response.Headers.TryGetValues("Link", out var links) && links.First().Split(',').FirstOrDefault(l => l.Contains("rel=\"next\"")) is { } next
        ? next[(next.IndexOf('<') + 1)..next.IndexOf('>')]
        : null;
}

var distinct = repos.GroupBy(r => KnownTemplateCheck.NormalizedHash(r.Template)).ToList();
Console.WriteLine($"{repos.Count} repos with templates, {distinct.Count} distinct templates\n");

var byRule = new Dictionary<string, List<(string Repo, Finding Finding)>>();
foreach (var group in distinct)
{
    var first = group.First();
    foreach (var f in ModelScanner.AnalyzeTemplate(first.Template, TemplateDialect.Jinja, first.Id).Where(f => f.Severity > Severity.Info))
    {
        var key = $"{f.RuleId} {f.Severity}";
        if (!byRule.TryGetValue(key, out var list)) byRule[key] = list = [];
        list.Add(($"{first.Id} (+{group.Count() - 1} same)", f));
    }
}

var debug = args.SkipWhile(a => a != "--debug").Skip(1).FirstOrDefault();       // print one template and our render of it
if (debug is not null)
{
    var match = distinct.FirstOrDefault(g => g.Any(r => r.Id == debug));
    if (match is null) { Console.WriteLine($"{debug} not in corpus"); return; }
    var e = TemplateExplainer.Explain(match.First().Template);
    Console.WriteLine("---- template ----");
    Console.WriteLine(match.First().Template);
    Console.WriteLine("---- ours ----");
    Console.WriteLine(e.Prompt ?? "ERROR: " + e.Error);
    return;
}

if (dump is not null)
{
    File.WriteAllText(dump, JsonSerializer.Serialize(distinct.ToDictionary(g => g.First().Id, g => g.First().Template)));
    Console.WriteLine($"Wrote {distinct.Count} templates to {dump}");
}
if (compare is not null)
{
    using var reference = JsonDocument.Parse(File.ReadAllText(compare));
    int same = 0, differ = 0, skipped = 0;
    foreach (var g in distinct)
    {
        if (!reference.RootElement.TryGetProperty(g.First().Id, out var expected) || expected.ValueKind != JsonValueKind.String) { skipped++; continue; }
        var ours = TemplateExplainer.Explain(g.First().Template).Prompt;
        if (ours == expected.GetString()) { same++; continue; }
        differ++;
        var a = ours ?? "(render failed)";
        var b = expected.GetString()!;
        var i = 0;
        while (i < a.Length && i < b.Length && a[i] == b[i]) i++;
        Console.WriteLine($"  differs: {g.First().Id} at char {i}: ours {JsonSerializer.Serialize(a.Substring(Math.Max(0, i - 15), Math.Min(40, a.Length - Math.Max(0, i - 15))))} vs jinja2 {JsonSerializer.Serialize(b.Substring(Math.Max(0, i - 15), Math.Min(40, b.Length - Math.Max(0, i - 15))))}");
    }
    Console.WriteLine($"Fidelity vs jinja2: {same} identical, {differ} different, {skipped} not rendered by jinja2\n");
    if (differ > 0) Environment.ExitCode = 1;
}

var renderErrors = distinct
    .Select(g => (Repo: g.First().Id, Error: TemplateExplainer.Explain(g.First().Template).Error))
    .Where(x => x.Error is not null)
    .ToList();
Console.WriteLine($"Rendered in the sandbox: {distinct.Count - renderErrors.Count}/{distinct.Count}");
foreach (var group in renderErrors.GroupBy(e => System.Text.RegularExpressions.Regex.Replace(e.Error!, @"'[^']*'|\d+", "_")).OrderByDescending(g => g.Count()).Take(12))
    Console.WriteLine($"  {group.Count(),3} x {group.First().Error}  e.g. {group.First().Repo}");
Console.WriteLine();

var flagged = distinct.Count(g => byRule.Values.Any(l => l.Any(x => x.Repo.StartsWith(g.First().Id + " ", StringComparison.Ordinal))));
Console.WriteLine($"Distinct templates with any warning (low+): {flagged}/{distinct.Count} ({flagged * 100.0 / Math.Max(1, distinct.Count):0.0}%)\n");
foreach (var (rule, hits) in byRule.OrderBy(k => k.Key))
{
    Console.WriteLine($"{rule,-14} {hits.Count,4}  e.g. {string.Join(", ", hits.Take(3).Select(h => h.Repo))}");
    if (show is not null && rule.StartsWith(show, StringComparison.Ordinal))
        foreach (var (repo, f) in hits)
            Console.WriteLine($"    {repo}: {f.Title}\n      {f.Detail.Replace("\n", "\n      ")}");
}
