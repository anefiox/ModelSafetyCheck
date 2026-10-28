using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Data;
using ModelSafetyCheck.Jinja;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Hub;

public sealed record RepoScanOptions(int MaxGgufFiles = 6, bool AllFiles = false, int BudgetMiB = 64);

/// <summary>
/// The `repo` command: checks a Hugging Face repo before you download it. Lure files and README
/// instructions (the fake "Privacy Filter" repo), publisher and lineage, and the chat template inside
/// each GGUF fetched header-only, compared with the template Hugging Face displays (Pillar's
/// clean-card / poisoned-file trick).
/// </summary>
public static partial class RepoScanner
{
    static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".scr", ".lnk", ".msi", ".msix", ".dmg", ".pkg", ".app", ".sh", ".command", ".jar", ".apk", ".so", ".dylib", ".elf", ".bin.exe" };
    static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase) { ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".xz", ".bz2", ".iso" };
    static readonly HashSet<string> PickleExtensions = new(StringComparer.OrdinalIgnoreCase) { ".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".joblib", ".npy" };

    [GeneratedRegex(@"abliterat|uncensor|unfilter|unaligned|jailbr|\bmerge\b|frankenmerge|-merge|merged|\bnsfw\b|heretic|decensor", RegexOptions.IgnoreCase)]
    private static partial Regex ModifiedMarkerRegex();

    [GeneratedRegex(@"-0000[2-9]-of-\d+\.gguf$|-\d{4}[1-9]-of-\d+\.gguf$", RegexOptions.IgnoreCase)]
    private static partial Regex LaterShardRegex();

    static readonly (Regex Pattern, string Description)[] ReadmeLures =
    [
        (new(@"\b(?:run|execute|double[- ]click|launch|open)\b[^.\n]{0,60}\.(?:bat|cmd|ps1|exe|vbs|sh|command|msi|dmg|lnk|scr)\b", RegexOptions.IgnoreCase), "tells you to run a script or executable"),
        (new(@"\bpython3?\s+(?!-m\s+pip)[\w./\\-]+\.py\b", RegexOptions.IgnoreCase), "tells you to run a Python script from the repo"),
        (new(@"(?:curl|wget|iwr|Invoke-WebRequest)\b[^\n|]{0,200}\|\s*(?:ba)?sh\b|\|\s*iex\b|\biex\s*\(", RegexOptions.IgnoreCase), "pipes a download straight into a shell"),
        (new(@"powershell(?:\.exe)?\s+(?:-\w+\s+)*-(?:enc|encodedcommand|e|c|command)\b", RegexOptions.IgnoreCase), "runs an inline PowerShell command"),
        (new(@"\b(?:disable|turn off|deactivate|whitelist|exclude)\b[^.\n]{0,40}\b(?:antivirus|anti-virus|defender|smartscreen|firewall|gatekeeper)\b", RegexOptions.IgnoreCase), "asks you to disable security software"),
        (new(@"\btrust_remote_code\s*=\s*True\b", RegexOptions.IgnoreCase), "requires trust_remote_code=True (runs repo code on load)"),
    ];

    public static List<ScanReport> Scan(HuggingFaceClient client, string repoInput, RepoScanOptions options)
    {
        var repo = HuggingFaceClient.NormalizeRepoId(repoInput);
        var report = new ScanReport { Target = $"hf:{repo ?? repoInput}", Kind = "hf-repo" };
        var reports = new List<ScanReport> { report };
        if (repo is null)
        {
            report.Error = "Not a Hugging Face repo id (expected 'org/name' or a huggingface.co URL).";
            return reports;
        }

        HfModelInfo info;
        try
        {
            info = client.GetModel(repo);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException or System.Text.Json.JsonException)
        {
            report.Error = ex.Message;
            return reports;
        }

        CheckPublisherAndLineage(info, report);
        CheckFiles(info, report);
        CheckReadme(client, repo, info, report);
        CheckTemplateFiles(client, repo, info, report);

        if (info.DisplayedGgufTemplate is { Length: > 0 } displayed)
            ModelScanner.ScanTemplate(report, displayed, TemplateDialect.Jinja, "template shown on Hugging Face");

        reports.AddRange(ScanGgufHeaders(client, repo, info, options, report));
        reports.AddRange(ScanOtherWeights(client, repo, info, options));
        return reports;
    }

    public static void CheckPublisherAndLineage(HfModelInfo info, ScanReport report)
    {
        var tier = ReferenceData.TierOf(info.Author);
        var lineage = info.Tags.Where(t => t.StartsWith("base_model:", StringComparison.Ordinal)).Select(t => t["base_model:".Length..]).ToList();
        var markers = ModifiedMarkerRegex().Matches(string.Join(" ", new[] { info.Id }.Concat(info.Tags).Concat(info.BaseModels)))
            .Select(m => m.Value.ToLowerInvariant()).Distinct().ToList();

        report.Findings.Add(new Finding("H001", Severity.Info, $"Published by {info.Author} ({TierText(tier)})",
            $"Created {info.CreatedAt:yyyy-MM-dd}, last modified {info.LastModified:yyyy-MM-dd}, {info.Downloads:N0} downloads in the last 30 days, {info.Files.Count} files." +
            (lineage.Count > 0 ? $"\nLineage: {string.Join(", ", lineage)}" : info.BaseModels.Count > 0 ? $"\nBase model: {string.Join(", ", info.BaseModels)}" : ""),
            "repo"));

        if (tier == PublisherTier.Unknown)
            report.Findings.Add(new Finding("H007", markers.Count > 0 ? Severity.Medium : Severity.Low, "Publisher is not an official lab or an established quantizer",
                $"'{info.Author}' is not in the trusted-publisher list. Treat these weights like a pull request from a stranger: fine for chatting, but do not give them tools, files or a shell. " +
                "A SHA-256 check only proves you got the file the uploader intended.", "repo"));

        if (markers.Count > 0)
            report.Findings.Add(new Finding("H006", tier == PublisherTier.Official ? Severity.Info : Severity.Low, "Modified model (abliterated / merged / uncensored)",
                $"Markers: {string.Join(", ", markers)}. These are usually built by stacking fine-tunes and merges from several people; nobody can audit the training pipeline, " +
                "and a backdoor trained into the weights survives quantization and is invisible to scanning.", "repo"));

        var age = info.CreatedAt is { } created ? DateTimeOffset.UtcNow - created : (TimeSpan?)null;
        if (age is { TotalDays: < 30 } && info.Downloads > 50_000 && tier == PublisherTier.Unknown)
            report.Findings.Add(new Finding("H008", Severity.Medium, "New repo with unusually high downloads",
                $"Created {age.Value.TotalDays:0} days ago with {info.Downloads:N0} downloads. Download counts can be inflated by bots to make a fake repo look trustworthy.", "repo"));
    }

    static void CheckFiles(HfModelInfo info, ScanReport report)
    {
        var executables = info.Files.Where(f => ExecutableExtensions.Contains(Path.GetExtension(f.Path))).Select(f => f.Path).ToList();
        if (executables.Count > 0)
            report.Findings.Add(new Finding("H002", Severity.High, "Repo contains executables or scripts",
                $"Model repos have no reason to ship these: {string.Join(", ", executables.Take(10))}. The fake 'Privacy Filter' repo used a .bat file and a Python loader to install an info-stealer. Do not run them.",
                "files"));

        var python = info.Files.Where(f => f.Path.EndsWith(".py", StringComparison.OrdinalIgnoreCase)).Select(f => f.Path).ToList();
        if (python.Count > 0)
            report.Findings.Add(new Finding("H002", Severity.Medium, "Repo contains Python code",
                $"{string.Join(", ", python.Take(10))}. Often legitimate model code (loaded with trust_remote_code), but it runs with your permissions: read it before using it.",
                "files"));

        var archives = info.Files.Where(f => ArchiveExtensions.Contains(Path.GetExtension(f.Path))).Select(f => f.Path).ToList();
        if (archives.Count > 0)
            report.Findings.Add(new Finding("H002", Severity.Medium, "Repo contains archives", $"{string.Join(", ", archives.Take(10))}. Archives hide their contents from Hugging Face's scanners.", "files"));

        var pickles = info.Files.Where(f => PickleExtensions.Contains(Path.GetExtension(f.Path))).Select(f => f.Path).ToList();
        if (pickles.Count > 0)
            report.Findings.Add(new Finding("H009", Severity.Medium, "Pickle-based weight files",
                $"{string.Join(", ", pickles.Take(10))}. Pickle can run code when loaded. Prefer the safetensors or GGUF files, or scan these with picklescan/modelscan first.",
                "files"));
    }

    static void CheckReadme(HuggingFaceClient client, string repo, HfModelInfo info, ScanReport report)
    {
        if (!info.Files.Any(f => f.Path.Equals("README.md", StringComparison.OrdinalIgnoreCase)))
            return;
        string? readme;
        try { readme = client.GetText(repo, "README.md", 512 * 1024); }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException) { return; }
        if (readme is null)
            return;

        var hits = ReadmeLures.SelectMany(l => l.Pattern.Matches(readme).Select(m => $"{l.Description}: \"{TextHeuristics.Truncate(m.Value, 100)}\"")).Distinct().ToList();
        if (hits.Count > 0)
        {
            var onlyRemoteCode = hits.All(h => h.StartsWith("requires trust_remote_code", StringComparison.Ordinal));
            var severity = onlyRemoteCode || ReferenceData.TierOf(info.Author) != PublisherTier.Unknown ? Severity.Medium : Severity.High;
            report.Findings.Add(new Finding("H003", severity, "Model card asks you to run something",
                "Legitimate GGUF repos are loaded by your runner; they do not need you to run scripts: " + string.Concat(hits.Take(6).Select(h => $"\n  - {h}")), "README.md"));
        }

        var invisible = TextHeuristics.ScanInvisible(readme);
        if (invisible.Tags > 0 || invisible.Bidi > 0)
            report.Findings.Add(new Finding("H003", invisible.Severity, "Hidden characters in the model card", $"Found {invisible.Describe()}.", "README.md"));

        // A card that names an official lab many times but is not published by it may be impersonating it.
        if (ReferenceData.TierOf(info.Author) == PublisherTier.Unknown && info.BaseModels.Count == 0)
        {
            var impersonated = ReferenceData.TrustedPublishers.Official
                .Select(org => (org, count: Regex.Matches(readme, $@"\b{Regex.Escape(org)}\b", RegexOptions.IgnoreCase).Count))
                .Where(x => x.count >= 3)
                .OrderByDescending(x => x.count)
                .FirstOrDefault();
            if (impersonated.org is not null)
                report.Findings.Add(new Finding("H008", Severity.Medium, $"Model card refers to {impersonated.org} but the repo is not theirs",
                    $"The card names '{impersonated.org}' {impersonated.count} times, declares no base model, and is published by '{info.Author}'. Fake repos copy official model cards; get the model from {HuggingFaceClient.Host}/{impersonated.org} instead.",
                    "README.md"));
        }
    }

    /// <summary>Non-GGUF repos: the template in chat_template.jinja / tokenizer_config.json is what transformers and vLLM render.</summary>
    static void CheckTemplateFiles(HuggingFaceClient client, string repo, HfModelInfo info, ScanReport report)
    {
        foreach (var name in new[] { "chat_template.jinja", "tokenizer_config.json" })
        {
            if (!info.Files.Any(f => f.Path == name))
                continue;
            string? text;
            try { text = client.GetText(repo, name, 4 << 20); }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException) { continue; }
            if (text is null)
                continue;

            if (name.EndsWith(".jinja", StringComparison.Ordinal))
            {
                ModelScanner.ScanTemplate(report, text, TemplateDialect.Jinja, name);
                return;
            }
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(text);
                if (!doc.RootElement.TryGetProperty("chat_template", out var t))
                    continue;
                if (t.ValueKind == System.Text.Json.JsonValueKind.String)
                    ModelScanner.ScanTemplate(report, t.GetString()!, TemplateDialect.Jinja, $"{name}:chat_template");
                else if (t.ValueKind == System.Text.Json.JsonValueKind.Array)
                    foreach (var item in t.EnumerateArray())
                        ModelScanner.ScanTemplate(report, item.GetProperty("template").GetString() ?? "", TemplateDialect.Jinja, $"{name}:chat_template.{item.GetProperty("name").GetString()}");
            }
            catch (Exception ex) when (ex is System.Text.Json.JsonException or KeyNotFoundException or InvalidOperationException)
            {
            }
        }
    }

    static IEnumerable<ScanReport> ScanGgufHeaders(HuggingFaceClient client, string repo, HfModelInfo info, RepoScanOptions options, ScanReport repoReport)
    {
        var ggufs = info.Files.Where(f => f.Path.EndsWith(".gguf", StringComparison.OrdinalIgnoreCase) && !LaterShardRegex().IsMatch(f.Path))
            .OrderBy(f => f.Size).ToList();
        if (ggufs.Count == 0)
            yield break;

        var selected = options.AllFiles || ggufs.Count <= options.MaxGgufFiles ? ggufs : Spread(ggufs, options.MaxGgufFiles);
        if (selected.Count < ggufs.Count)
            repoReport.Findings.Add(new Finding("H004", Severity.Info, "Not every GGUF file was checked",
                $"Checked {selected.Count} of {ggufs.Count} GGUF files (spread across sizes). A poisoned template can hide in a single quant: use --all-files to check every one.", "files"));

        var displayedHash = info.DisplayedGgufTemplate is { Length: > 0 } d ? KnownTemplateCheck.NormalizedHash(d) : null;
        var templatesByFile = new List<(string File, string Template, bool Suspicious)>();

        foreach (var file in selected)
        {
            var fileReport = new ScanReport { Target = $"hf:{repo}/{file.Path}", Kind = "hf-gguf", Fingerprint = file.Sha256 };
            try
            {
                using var stream = new HttpRangeStream(client.Http, client.FileUrl(repo, file.Path), (long)options.BudgetMiB << 20);
                ModelScanner.ScanGguf(stream, fileReport);
                fileReport.Findings.Add(new Finding("H004", Severity.Info, "Header fetched without downloading the model",
                    $"Read {stream.Downloaded / 1024.0 / 1024.0:0.0} MiB of {file.Size / 1024.0 / 1024.0 / 1024.0:0.00} GiB. LFS sha256 {file.Sha256 ?? "unknown"}.", file.Path));
            }
            catch (Exception ex) when (ex is IOException or HttpRequestException or TaskCanceledException)
            {
                fileReport.Error = ex.Message;
            }

            var templateWarnings = fileReport.Findings.Any(f => f.RuleId.StartsWith('T') && f.Severity >= Severity.Medium);
            foreach (var t in fileReport.Templates.Where(t => t.Location == "kv:tokenizer.chat_template"))
                templatesByFile.Add((file.Path, t.Text, templateWarnings));
            yield return fileReport;
        }

        // Pillar: the card can display a clean template while a downloadable file carries a poisoned one.
        // A mismatch whose template is otherwise clean is usually a stale upload, so it rates lower.
        foreach (var (path, template, suspicious) in templatesByFile)
        {
            if (displayedHash is null || KnownTemplateCheck.NormalizedHash(template) == displayedHash)
                continue;
            var (added, removed, similarity) = KnownTemplateCheck.Compare(template, info.DisplayedGgufTemplate!);
            repoReport.Findings.Add(new Finding("H005", suspicious ? Severity.High : Severity.Medium, "A GGUF file's template differs from the one Hugging Face displays",
                $"{path} embeds a template {similarity:P0} similar to the displayed one ({added.Count} line(s) added, {removed.Count} removed). " +
                "What you review on the website is not what will run. " +
                (suspicious ? "The file's template also triggered template warnings (see that file's findings). " : "The file's template raised no other warnings, so this is most likely an older upload that was not refreshed. ") +
                "Lines only in the file:" +
                string.Concat(added.OrderByDescending(l => TextHeuristics.CountWords(l)).Take(6).Select(l => $"\n  + {TextHeuristics.Truncate(l, 140)}")),
                path));
        }

        var distinct = templatesByFile.Select(t => KnownTemplateCheck.NormalizedHash(t.Template)).Distinct().Count();
        if (distinct > 1 && displayedHash is null)
            repoReport.Findings.Add(new Finding("H005", Severity.High, "GGUF files in this repo embed different templates",
                $"{distinct} different chat templates across {templatesByFile.Count} files. Quantizations of one model should share a template.", "files"));
    }

    /// <summary>
    /// Pickle checkpoints and safetensors headers, read remotely. A PyTorch zip keeps its index at the end and
    /// data.pkl is small, so only a few MiB of a multi-gigabyte .bin are fetched.
    /// </summary>
    static IEnumerable<ScanReport> ScanOtherWeights(HuggingFaceClient client, string repo, HfModelInfo info, RepoScanOptions options)
    {
        var pickles = info.Files.Where(f => PickleScanner.Extensions.Contains(Path.GetExtension(f.Path))).Take(options.AllFiles ? 50 : 3);
        var safetensors = info.Files.Where(f => f.Path.EndsWith(".safetensors", StringComparison.OrdinalIgnoreCase)).Take(options.AllFiles ? 50 : 2);
        foreach (var file in pickles.Concat(safetensors))
        {
            var isPickle = PickleScanner.Extensions.Contains(Path.GetExtension(file.Path));
            var report = new ScanReport { Target = $"hf:{repo}/{file.Path}", Kind = isPickle ? "hf-pickle" : "hf-safetensors", Fingerprint = file.Sha256 };
            try
            {
                using var stream = new HttpRangeStream(client.Http, client.FileUrl(repo, file.Path), (long)options.BudgetMiB << 20);
                if (isPickle) PickleScanner.Scan(stream, report);
                else SafetensorsScanner.Scan(stream, report);
                report.Findings.Add(new Finding("H004", Severity.Info, "Checked without downloading the file",
                    $"Read {stream.Downloaded / 1024.0 / 1024.0:0.0} MiB of {file.Size / 1024.0 / 1024.0:0.0} MiB.", file.Path));
            }
            catch (Exception ex) when (ex is IOException or HttpRequestException or TaskCanceledException or InvalidDataException)
            {
                report.Error = ex.Message;
            }
            yield return report;
        }
    }

    static List<HfFile> Spread(List<HfFile> sorted, int count)
    {
        if (count <= 1) return [sorted[0]];
        return Enumerable.Range(0, count).Select(i => sorted[(int)Math.Round(i * (sorted.Count - 1) / (double)(count - 1))]).Distinct().ToList();
    }

    static string TierText(PublisherTier tier) => tier switch
    {
        PublisherTier.Official => "official publisher",
        PublisherTier.Quantizer => "established quantizer",
        _ => "unknown publisher",
    };
}
