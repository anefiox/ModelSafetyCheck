using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Jinja;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Hub;

/// <summary>
/// `repo ollama:&lt;model&gt;` (F-04): checks an Ollama registry model before `ollama pull`. Reads the manifest,
/// the template and system layers (the prompt formatting that will actually run), and the GGUF header of the
/// model layer through HTTP Range requests, without downloading the weights.
/// </summary>
public static partial class OllamaRegistryScanner
{
    const string Registry = "https://registry.ollama.ai";

    [GeneratedRegex("^sha256:[0-9a-f]{64}$")]
    private static partial Regex DigestRegex();

    [GeneratedRegex(@"^(?:(?<ns>[a-z0-9][a-z0-9._-]*)/)?(?<model>[a-z0-9][a-z0-9._-]*)(?::(?<tag>[\w.-]+))?$", RegexOptions.IgnoreCase)]
    private static partial Regex NameRegex();

    public static bool IsOllamaName(string input) =>
        input.StartsWith("ollama:", StringComparison.OrdinalIgnoreCase) || input.StartsWith("ollama.com/", StringComparison.OrdinalIgnoreCase);

    public static List<ScanReport> Scan(HuggingFaceClient client, string input, RepoScanOptions options)
    {
        var name = Regex.Replace(input, "^(ollama:|ollama.com/|https://ollama.com/)", "", RegexOptions.IgnoreCase);

        // Ollama can pull straight from Hugging Face; check the source repo instead.
        if (name.StartsWith("hf.co/", StringComparison.OrdinalIgnoreCase) || name.StartsWith("huggingface.co/", StringComparison.OrdinalIgnoreCase))
            return RepoScanner.Scan(client, name[(name.IndexOf('/') + 1)..].Split(':')[0], options);

        var report = new ScanReport { Target = $"ollama:{name}", Kind = "ollama-registry" };
        var reports = new List<ScanReport> { report };
        var m = NameRegex().Match(name);
        if (!m.Success)
        {
            report.Error = "Not an Ollama model name (expected 'model', 'model:tag' or 'user/model:tag').";
            return reports;
        }
        var ns = m.Groups["ns"].Success ? m.Groups["ns"].Value : "library";
        var model = m.Groups["model"].Value;
        var tag = m.Groups["tag"].Success ? m.Groups["tag"].Value : "latest";
        var basePath = $"{Registry}/v2/{ns}/{model}";

        report.Findings.Add(ns == "library"
            ? new Finding("P001", Severity.Info, "Ollama library model", $"{ns}/{model}:{tag} is in Ollama's curated library.", "registry")
            : new Finding("H007", Severity.Low, "Community upload to the Ollama registry",
                $"'{ns}' is a registry user, not Ollama's library. Treat these weights like a stranger's pull request: fine for chatting, not for agents with tools.", "registry"));

        JsonDocument manifest;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{basePath}/manifests/{tag}");
            request.Headers.Accept.ParseAdd("application/vnd.docker.distribution.manifest.v2+json");
            using var response = client.Http.Send(request);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                report.Error = $"{ns}/{model}:{tag} was not found in the Ollama registry.";
                return reports;
            }
            response.EnsureSuccessStatusCode();
            manifest = JsonDocument.Parse(response.Content.ReadAsStream());
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or IOException)
        {
            report.Error = ex.Message;
            return reports;
        }

        using (manifest)
        {
            foreach (var layer in manifest.RootElement.GetProperty("layers").EnumerateArray())
            {
                var mediaType = layer.GetProperty("mediaType").GetString() ?? "";
                var digest = layer.GetProperty("digest").GetString() ?? "";
                var size = layer.TryGetProperty("size", out var s) && s.TryGetInt64(out var n) ? n : 0;
                if (!DigestRegex().IsMatch(digest))
                {
                    report.Findings.Add(new Finding("O001", Severity.High, "Malformed layer digest in the registry manifest",
                        $"'{digest}' is not a sha256 digest; crafted digests were used for path traversal (CVE-2024-37032).", "manifest"));
                    continue;
                }
                var blobUrl = new Uri($"{basePath}/blobs/{digest}");
                try
                {
                    switch (mediaType)
                    {
                        case "application/vnd.ollama.image.template" when size <= 1 << 20:
                            ModelScanner.ScanTemplate(report, client.Http.GetStringAsync(blobUrl).GetAwaiter().GetResult(), TemplateDialect.GoTemplate, "ollama template layer");
                            break;
                        case "application/vnd.ollama.image.system" when size <= 1 << 20:
                            ModelScanner.ScanSystemPrompt(report, client.Http.GetStringAsync(blobUrl).GetAwaiter().GetResult(), "ollama system layer");
                            break;
                        case "application/vnd.ollama.image.model" or "application/vnd.ollama.image.projector" or "application/vnd.ollama.image.adapter":
                            var label = mediaType[(mediaType.LastIndexOf('.') + 1)..];
                            var fileReport = new ScanReport { Target = $"ollama:{ns}/{model}:{tag} ({label} layer)", Kind = "ollama-registry", Fingerprint = digest };
                            using (var stream = new HttpRangeStream(client.Http, blobUrl, (long)options.BudgetMiB << 20))
                            {
                                ModelScanner.ScanGguf(stream, fileReport);
                                fileReport.Findings.Add(new Finding("H004", Severity.Info, "Header fetched without downloading the model",
                                    $"Read {stream.Downloaded / 1024.0 / 1024.0:0.0} MiB of {size / 1024.0 / 1024.0 / 1024.0:0.00} GiB.", label));
                            }
                            reports.Add(fileReport);
                            break;
                    }
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
                {
                    report.Findings.Add(new Finding("H004", Severity.Low, $"Could not read the {mediaType} layer", ex.Message, digest));
                }
            }
        }

        if (report.Templates.Count > 0 && reports.Skip(1).Any(r => r.Templates.Count > 0))
            report.Findings.Add(new Finding("O003", Severity.Info, "Ollama template overrides the embedded template",
                "Ollama will use the template layer, not the GGUF's chat template. Both were checked.", "ollama template layer"));
        return reports;
    }
}
