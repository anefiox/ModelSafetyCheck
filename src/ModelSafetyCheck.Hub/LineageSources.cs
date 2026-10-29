using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Rules;
using ModelSafetyCheck.Rules.Lineage;

namespace ModelSafetyCheck.Hub;

/// <summary>Opens GGUFs for a lineage comparison: local files, <c>hf:org/repo/file.gguf</c>, or HTTPS URLs (read with Range requests).</summary>
public static partial class LineageSources
{
    public sealed class Opened(LineageInput input, IDisposable owner, Func<long> downloaded) : IDisposable
    {
        public LineageInput Input { get; } = input;
        public long Downloaded => downloaded();
        public void Dispose() => owner.Dispose();
    }

    [GeneratedRegex(@"^(?:hf:|https?://(?:huggingface\.co|hf\.co)/)(?<repo>[^/]+/[^/]+)/(?:(?:resolve|blob)/(?<rev>[^/]+)/)?(?<path>.+\.gguf)$", RegexOptions.IgnoreCase)]
    private static partial Regex HfFileRegex();

    public static Opened Open(string spec, HuggingFaceClient client, long budgetBytes)
    {
        if (File.Exists(spec))
        {
            var stream = new FileStream(spec, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);
            return new Opened(LineageInput.FromFile(spec, stream), stream, () => 0);
        }

        Uri url;
        string name;
        if (HfFileRegex().Match(spec) is { Success: true } m)
        {
            var repo = m.Groups["repo"].Value;
            var path = m.Groups["path"].Value;
            url = client.FileUrl(repo, path, m.Groups["rev"].Success ? m.Groups["rev"].Value : "main");
            name = $"hf:{repo}/{path}";
        }
        else if (Uri.TryCreate(spec, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps)
        {
            url = u;
            name = spec;
        }
        else
            throw new FileNotFoundException($"'{spec}' is not a local file, an hf:org/repo/file.gguf reference or an HTTPS URL.");

        var remote = new HttpRangeStream(client.Http, url, budgetBytes);
        try
        {
            var file = GgufParser.Parse(remote);
            if (!file.TensorInfoComplete)
                throw new InvalidDataException($"{name}: the GGUF header could not be read completely ({string.Join("; ", file.ParseFindings.Select(f => f.Title))}).");
            return new Opened(new LineageInput(name, file, remote.ReadRange), remote, () => remote.Downloaded);
        }
        catch
        {
            remote.Dispose();
            throw;
        }
    }

    /// <summary>
    /// For a repo that declares <c>base_model:quantized:&lt;base&gt;</c>, finds a higher-precision GGUF of that base to compare
    /// against: ggml-org's conversions first, then "&lt;base&gt;-GGUF" from the base's own org. Prefers BF16/F16, then Q8_0.
    /// </summary>
    public static string? FindOfficialBase(HuggingFaceClient client, string baseRepo, out string? note)
    {
        note = null;
        var name = baseRepo.Split('/')[^1];
        // ggml-org (llama.cpp's maintainers) converts directly; some labs' own GGUFs are AWQ-style conversions (see L005).
        foreach (var candidate in new[] { $"ggml-org/{name}-GGUF", $"ggml-org/{name}-Q8_0-GGUF", $"ggml-org/{name}-F16-GGUF", $"{baseRepo}-GGUF" })
        {
            HfModelInfo info;
            try { info = client.GetModel(candidate); }
            catch (HttpRequestException) { continue; }
            var file = info.Files.Where(f => f.Path.EndsWith(".gguf", StringComparison.OrdinalIgnoreCase) && !f.Path.Contains("-of-0", StringComparison.Ordinal) && !f.Path.Contains("mmproj", StringComparison.OrdinalIgnoreCase))
                .Select(f => (File: f, Rank: Rank(f.Path)))
                .Where(x => x.Rank < 9)
                .OrderBy(x => x.Rank).ThenBy(x => x.File.Size)
                .FirstOrDefault();
            if (file.File is not null)
                return $"hf:{info.Id}/{file.File.Path}";
            note = $"{candidate} has no single-file F16/BF16/Q8_0 GGUF.";
        }
        note ??= $"No F16/BF16/Q8_0 GGUF of {baseRepo} found (ggml-org/{name}-GGUF or {baseRepo}-GGUF). Pass a base with 'modelcheck lineage <file> --base <gguf>'.";
        return null;

        static int Rank(string path)
        {
            var p = path.ToLowerInvariant();
            return p.Contains("bf16") ? 0 : p.Contains("f16") ? 1 : p.Contains("q8_0") ? 2 : 9;
        }
    }

    /// <summary>Compares a candidate against a base and returns the lineage report.</summary>
    public static ScanReport Check(HuggingFaceClient client, string candidate, string @base, long budgetBytes, LineageOptions? options = null, string? claim = null)
    {
        var report = new ScanReport { Target = candidate, Kind = "lineage" };
        try
        {
            using var c = Open(candidate, client, budgetBytes);
            using var b = Open(@base, client, budgetBytes);
            var result = WeightLineage.Compare(c.Input, b.Input, options);
            report = WeightLineage.ToReport(result, claim);
            if (c.Downloaded + b.Downloaded > 0)
                report.Findings.Add(new Finding("H004", Severity.Info, "Weights sampled without downloading the models",
                    $"Read {c.Downloaded / 1048576.0:0.0} MiB of the candidate and {b.Downloaded / 1048576.0:0.0} MiB of the base with Range requests.", "weights"));
        }
        catch (Exception ex) when (ex is IOException or HttpRequestException or InvalidDataException or OperationCanceledException or UnauthorizedAccessException)
        {
            report.Error = ex.Message;
        }
        return report;
    }
}
