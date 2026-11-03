using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Hub;

public sealed record DownloadFile(string Url, string Path, long? Size = null, string? Sha256 = null, string? TokenEnvironment = null);
public sealed record DownloadJob(string Id, List<DownloadFile> Files, string? Revision = null, string? Error = null);
public sealed record DownloadManifest(List<DownloadJob> Models);

/// <summary>Provider-neutral file sets, plus a Hugging Face adapter that pins commits and groups shards.</summary>
public static partial class DownloadPlan
{
    public static readonly IReadOnlyList<string> TextTasks = ["text-generation", "text2text-generation", "fill-mask",
        "feature-extraction", "sentence-similarity", "text-classification", "token-classification", "question-answering",
        "summarization", "translation", "zero-shot-classification", "table-question-answering"];

    [GeneratedRegex(@"^(?<prefix>.*?)-(?<part>\d{5,6})-of-(?<total>\d{5,6})(?<extension>\.(?:gguf|safetensors|bin))$", RegexOptions.IgnoreCase)]
    private static partial Regex ShardPattern();

    public static DownloadManifest ReadManifest(string path)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length > 16 << 20) throw new InvalidDataException("Manifest exceeds 16 MiB.");
        var manifest = JsonSerializer.Deserialize(stream, BatchJsonContext.Default.DownloadManifest)
            ?? throw new InvalidDataException("Empty download manifest.");
        if (manifest.Models is null) throw new InvalidDataException("Manifest needs a models list.");
        foreach (var job in manifest.Models) Validate(job);
        return manifest;
    }

    public static DownloadJob FromUrl(string source)
    {
        var uri = ValidateUrl(source);
        var name = Uri.UnescapeDataString(uri.AbsolutePath.Split('/')[^1]);
        if (!ModelScanner.IsScannable(name))
            throw new InvalidDataException("A direct URL must name a supported model/template file. For download endpoints, use a manifest with an explicit path.");
        var job = new DownloadJob(DisplayUrl(source), [new DownloadFile(source, name)]);
        Validate(job);
        return job;
    }

    public static IEnumerable<DownloadJob> FromHuggingFace(HuggingFaceClient client, string repo)
    {
        var info = client.GetModel(repo);
        if (info.Revision is null || !Regex.IsMatch(info.Revision, "^[a-fA-F0-9]{40}$"))
            throw new InvalidDataException("Hugging Face did not return an immutable commit SHA.");
        var weights = info.Files.Where(f => IsWeight(f.Path)).ToList();
        if (weights.Count == 0) throw new InvalidDataException("Repository has no supported weight files.");
        foreach (var group in weights.GroupBy(f => GroupKey(f.Path)))
        {
            var files = group.ToList();
            ValidateShards(files);
            var dirs = files.Select(f => DirectoryPart(f.Path)).Append("").ToHashSet(StringComparer.Ordinal);
            // Templates/configs accompany every relevant representation. ONNX external-data files must also be present locally.
            var companions = info.Files.Where(f => !IsWeight(f.Path) && dirs.Contains(DirectoryPart(f.Path)) &&
                (ModelScanner.IsScannable(f.Path) || f.Path.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ||
                 files.Any(w => w.Path.EndsWith(".onnx", StringComparison.OrdinalIgnoreCase)) &&
                    Path.GetExtension(f.Path).ToLowerInvariant() is ".data" or ".onnx_data"));
            var selected = files.Concat(companions).DistinctBy(f => f.Path).ToList();
            if (selected.Any(f => f.Size <= 0))
                throw new InvalidDataException($"Unknown or invalid file size in {repo}/{group.Key}; refusing to assume it fits the size limit.");
            var job = new DownloadJob($"hf:{repo}/{group.Key}", selected.Select(f => new DownloadFile(
                client.FileUrl(repo, f.Path, info.Revision).AbsoluteUri, f.Path, f.Size, f.Sha256)).ToList(), info.Revision);
            Validate(job);
            yield return job;
        }
    }

    /// <summary>
    /// One variant of a repository's file sets: the smallest below <paramref name="maxBytes"/> (or, when none fits, the
    /// smallest, so the size limit is still reported). Files that ship beside a model without being one (vision
    /// projectors, imatrix calibration data, vocabularies, training state, or anything under 2% of the repository's
    /// largest set) are never chosen, and pickle-only sets rank after safetensors, GGUF and ONNX, which usually hold the
    /// same weights. Errors pass through.
    /// </summary>
    public static IEnumerable<DownloadJob> SmallestModel(IEnumerable<DownloadJob> jobs, long maxBytes)
    {
        var all = jobs.ToList();
        var sized = all.Where(j => j.Error is null)
            .Select(j => (Job: j, Size: j.Files.Sum(f => f.Size ?? long.MaxValue / j.Files.Count))).ToList();
        var largest = sized.Count > 0 ? sized.Max(j => j.Size) : 0;
        var models = sized.Where(j => !Auxiliary(j.Job.Id) && j.Size >= largest / 50)
            .OrderBy(j => j.Size >= maxBytes)
            .ThenBy(j => !j.Job.Files.Any(f => Path.GetExtension(f.Path).ToLowerInvariant() is ".gguf" or ".safetensors" or ".onnx"))
            .ThenBy(j => j.Size).ThenBy(j => j.Job.Id, StringComparer.Ordinal).ToList();
        if (models.Count > 0) yield return models[0].Job;
        else if (sized.Count > 0) yield return new DownloadJob(string.Join('/', sized[0].Job.Id.Split('/').Take(2)), [],
            Error: "No file set looks like the model itself (only projectors, calibration data or other auxiliary files).");
        foreach (var error in all.Where(j => j.Error is not null)) yield return error;
    }

    /// <summary>Job ids are "hf:org/name/&lt;path&gt;"; only the path is matched, not the repository name.</summary>
    static bool Auxiliary(string id) => id.Split('/', 3) is [_, _, var path] &&
        new[] { "mmproj", "imatrix", "vocab", "training_args", "optimizer", "vision/" }
            .Any(word => path.Contains(word, StringComparison.OrdinalIgnoreCase));

    static bool IsWeight(string path) => Path.GetExtension(path).ToLowerInvariant() is ".gguf" or ".safetensors" or ".onnx" ||
        PickleScanner.Extensions.Contains(Path.GetExtension(path));

    static string DirectoryPart(string path) => path.Contains('/') ? path[..(path.LastIndexOf('/') + 1)] : "";

    static string GroupKey(string path)
    {
        var shard = ShardPattern().Match(path);
        return shard.Success ? $"{shard.Groups["prefix"].Value}-shards{shard.Groups["extension"].Value}" : path;
    }

    static void ValidateShards(List<HfFile> files)
    {
        var first = ShardPattern().Match(files[0].Path);
        if (!first.Success) return;
        var total = int.Parse(first.Groups["total"].Value, System.Globalization.CultureInfo.InvariantCulture);
        var parts = files.Select(f => ShardPattern().Match(f.Path)).ToList();
        var numbers = parts.Select(m => int.Parse(m.Groups["part"].Value, System.Globalization.CultureInfo.InvariantCulture))
            .Order().ToList();
        // Usually 1..N of N. Some exporters number from zero, ending at N-1 or at N (gpt-oss: 00000..00002-of-00002).
        if (total == 0 || parts.Any(m => int.Parse(m.Groups["total"].Value,
            System.Globalization.CultureInfo.InvariantCulture) != total) ||
            !numbers.SequenceEqual(Enumerable.Range(1, total)) && !numbers.SequenceEqual(Enumerable.Range(0, total)) &&
            !numbers.SequenceEqual(Enumerable.Range(0, total + 1)))
            throw new InvalidDataException("Missing, duplicate or inconsistent model shards.");
    }

    public static void Validate(DownloadJob job)
    {
        if (job is null || string.IsNullOrWhiteSpace(job.Id) || job.Files is not { Count: > 0 })
            throw new InvalidDataException("Every model needs an id and a nonempty files list.");
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in job.Files)
        {
            if (file is null) throw new InvalidDataException("Null file entry.");
            ValidateUrl(file.Url);
            ValidatePath(file.Path);
            if (!paths.Add(file.Path)) throw new InvalidDataException("Duplicate or case-colliding download paths.");
            if (file.Size is < 0) throw new InvalidDataException("Negative file size.");
            if (file.Sha256 is not null && !Regex.IsMatch(file.Sha256, "^[a-fA-F0-9]{64}$"))
                throw new InvalidDataException("Expected SHA-256 must contain 64 hexadecimal characters.");
            if (file.TokenEnvironment is not null && (file.TokenEnvironment.Length == 0 || file.TokenEnvironment.Any(char.IsControl)))
                throw new InvalidDataException("Invalid bearer token environment-variable name.");
        }
        if (!job.Files.Any(f => ModelScanner.IsScannable(f.Path)))
            throw new InvalidDataException("Model file set has no supported file to scan.");
        foreach (var group in job.Files.Where(f => ShardPattern().IsMatch(f.Path)).GroupBy(f => GroupKey(f.Path)))
            ValidateShards(group.Select(f => new HfFile(f.Path, f.Size ?? 0, f.Sha256)).ToList());
    }

    public static void ValidatePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 1024 || path.Contains('\\') || path.Contains(':') || path.StartsWith('/'))
            throw new InvalidDataException("Download paths must be portable relative paths using forward slashes.");
        foreach (var part in path.Split('/'))
        {
            var stem = part.Split('.')[0];
            if (part is "" or "." or ".." || part.EndsWith('.') || part.EndsWith(' ') || part.Any(c => c < 32 || "<>\"|?*".Contains(c)) ||
                Regex.IsMatch(stem, "^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])$", RegexOptions.IgnoreCase))
                throw new InvalidDataException("Unsafe download path component.");
        }
    }

    public static Uri ValidateUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") || uri.UserInfo.Length > 0)
            throw new InvalidDataException("Download sources must be HTTP(S) URLs without embedded credentials.");
        return uri;
    }

    public static string DisplayUrl(string url)
    {
        var uri = ValidateUrl(url);
        return uri.GetLeftPart(UriPartial.Path); // Query strings may contain signed download credentials.
    }

    public static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true,
    UseStringEnumConverter = true)]
[JsonSerializable(typeof(DownloadManifest))]
[JsonSerializable(typeof(DownloadJob))]
[JsonSerializable(typeof(BatchResult))]
public sealed partial class BatchJsonContext : JsonSerializerContext;
