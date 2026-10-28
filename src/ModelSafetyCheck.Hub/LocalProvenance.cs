using System.Security.Cryptography;
using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Hub;

/// <summary>
/// `local --online` (H-10): maps installed models back to their Hugging Face repo, then checks the
/// publisher and lineage and whether the local file is still the published one (size, optionally
/// sha256). A hash only proves you have what the uploader published, so the publisher check matters more.
/// </summary>
public static partial class LocalProvenance
{
    [GeneratedRegex(@"[\\/]models--(?<org>[^\\/]+?)--(?<name>[^\\/]+)[\\/]snapshots[\\/][^\\/]+[\\/](?<file>.+)$")]
    private static partial Regex HubCachePathRegex();

    public static (string Repo, string? File)? RepoOf(ScanReport report)
    {
        if (report.Kind == "lmstudio" && report.Target.StartsWith("lmstudio:", StringComparison.Ordinal))
        {
            var parts = report.Target["lmstudio:".Length..].Split('/');
            return parts.Length >= 3 ? ($"{parts[0]}/{parts[1]}", string.Join('/', parts[2..])) : null;
        }
        if (report.Kind == "hf-cache" && report.Path is not null)
        {
            var m = HubCachePathRegex().Match(report.Target.Replace("hf-cache:", "/"));
            return m.Success ? ($"{m.Groups["org"].Value}/{m.Groups["name"].Value}", m.Groups["file"].Value.Replace('\\', '/')) : null;
        }
        // Ollama can pull straight from Hugging Face: ollama:hf.co/org/repo:tag. The quant file is not recorded.
        if (report.Kind == "ollama" && report.Target.StartsWith("ollama:hf.co/", StringComparison.OrdinalIgnoreCase))
        {
            var name = report.Target["ollama:hf.co/".Length..];
            var colon = name.LastIndexOf(':');
            return (colon > 0 ? name[..colon] : name, null);
        }
        return null;
    }

    public static void Check(HuggingFaceClient client, IEnumerable<ScanReport> reports, bool verifyHash, Dictionary<string, HfModelInfo?>? cache = null)
    {
        cache ??= [];
        foreach (var report in reports)
        {
            if (report.Kind == "ollama" && report.Target.StartsWith("ollama:", StringComparison.Ordinal) && !report.Target.Contains("hf.co/", StringComparison.OrdinalIgnoreCase))
            {
                report.Findings.Add(new Finding("P001", Severity.Info, "From the Ollama registry",
                    report.Target.Contains('/') ? "A community upload to the Ollama registry, not an official library model: treat it like an unknown publisher." : "An Ollama library model.", "provenance"));
                continue;
            }
            if (RepoOf(report) is not { } source)
                continue;

            if (!cache.TryGetValue(source.Repo, out var info))
            {
                try { info = client.GetModel(source.Repo); }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException or System.Text.Json.JsonException) { info = null; }
                cache[source.Repo] = info;
            }
            if (info is null)
            {
                report.Findings.Add(new Finding("P002", Severity.Low, "Source repo not found on Hugging Face",
                    $"Expected {HuggingFaceClient.Host}/{source.Repo}. It may have been deleted or made private, which is worth knowing for a model you still run.", "provenance"));
                continue;
            }

            RepoScanner.CheckPublisherAndLineage(info, report);
            if (source.File is null || report.Path is null)
                continue;

            var published = info.Files.FirstOrDefault(f => f.Path == source.File);
            var localSize = new FileInfo(report.Path).Length;
            if (published is null)
            {
                report.Findings.Add(new Finding("P002", Severity.Low, "File is no longer in its repo",
                    $"{source.File} is not in {source.Repo} any more. It was renamed or removed, so it cannot be verified.", "provenance"));
                continue;
            }
            if (published.Size != localSize)
            {
                report.Findings.Add(new Finding("P003", Severity.Low, "Local file differs from the current upload",
                    $"Local size {localSize:N0} bytes, published {published.Size:N0}. Usually an older download that was later re-uploaded (e.g. with a fixed template). Run `modelcheck repo {source.Repo}` to compare templates.", "provenance"));
                continue;
            }
            if (!verifyHash || published.Sha256 is null)
            {
                report.Findings.Add(new Finding("P003", Severity.Info, "Same size as the published file",
                    $"Matches {source.Repo}/{source.File} by size. Add --hash to verify the sha256.", "provenance"));
                continue;
            }

            var sha = HashFile(report.Path);
            report.Findings.Add(sha == published.Sha256
                ? new Finding("P003", Severity.Info, "Identical to the published file", $"sha256 {sha} matches {source.Repo}/{source.File}.", "provenance")
                : new Finding("P003", Severity.High, "Same size as the published file but different contents",
                    $"sha256 {sha} does not match the published {published.Sha256}. A same-size change suggests the file was modified after download.", "provenance"));
        }
    }

    static string HashFile(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4 << 20);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }
}
