using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Data;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Hub;

public sealed record BatchOptions(string Directory, long MaxBytes = 100_000_000_000,
    long MaxTotalBytes = 1_000_000_000_000, bool KeepDownloads = false, bool DryRun = false, bool Force = false);
public sealed record DownloadReceipt(string Path, string Source, long Size, string Sha256);
public sealed record BatchResult(string Id, string? Revision, string Scanner, DateTimeOffset FinishedAt,
    bool Completed, List<DownloadReceipt> Files, List<ScanReport> Reports);

/// <summary>Downloads inert files into an isolated directory, scans them, and checkpoints one result per file set.</summary>
public sealed class BatchScanner : IDisposable
{
    readonly HttpClient _http;
    long _downloaded;

    public BatchScanner(HttpMessageHandler? handler = null) => _http = RemoteHttp.Create(handler);
    public long DownloadedBytes => _downloaded;

    static string ScannerIdentity => DownloadPlan.Hash(string.Join('|',
        typeof(BatchScanner).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Single(a => a.Key == "ScannerSources").Value,
        JsonSerializer.Serialize(ReferenceData.KnownTemplates, DataJsonContext.Default.KnownTemplateFile),
        JsonSerializer.Serialize(ReferenceData.TrustedPublishers, DataJsonContext.Default.TrustedPublisherFile)));

    public IEnumerable<ScanReport> Scan(IEnumerable<DownloadJob> jobs, BatchOptions options,
        Action<string>? progress = null, CancellationToken cancellationToken = default)
    {
        if (options.MaxBytes <= 0 || options.MaxTotalBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(options), "Download byte limits must be positive.");
        var root = Path.GetFullPath(options.Directory);
        _downloaded = 0;
        var scanner = ScannerIdentity;
        if (!options.DryRun)
        {
            System.IO.Directory.CreateDirectory(root);
            // Do not let concurrent runs replace each other's result files or exceed the same disk budget.
        }
        using var runLock = options.DryRun ? null : new FileStream(Path.Combine(root, "batch.lock"),
            FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        foreach (var job in jobs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (job.Error is not null)
            {
                yield return Failure(job.Id, job.Error);
                continue;
            }
            DownloadPlan.Validate(job);
            var key = DownloadPlan.Hash(JsonSerializer.Serialize(job, BatchJsonContext.Default.DownloadJob) + scanner);
            var resultPath = Path.Combine(root, "results", key + ".json");
            var knownSize = job.Files.All(f => f.Size is not null) ? job.Files.Sum(f => checked(f.Size!.Value)) : (long?)null;
            if (knownSize >= options.MaxBytes)
            {
                progress?.Invoke($"Skipped {job.Id}: {knownSize:N0} bytes meets or exceeds the per-model limit.");
                yield return Notice(job.Id, "Model exceeds size limit", $"{knownSize:N0} bytes; limit is strictly below {options.MaxBytes:N0}.");
                continue;
            }
            if (options.DryRun)
            {
                yield return Notice(job.Id, "Download plan", $"{job.Files.Count} file(s), " +
                    (knownSize is { } bytes ? $"{bytes:N0} bytes" : "unknown total size; the streaming limit will apply") +
                    $", revision {job.Revision ?? "unversioned"}. No model files downloaded.");
                continue;
            }
            // Plain URLs can change. Only pinned HF commits or fully hashed manifests can reuse an earlier scan.
            var immutable = job.Files.All(f => f.Sha256 is not null) || job.Files.All(f =>
                job.Revision is { Length: 40 } revision && IsPinnedHuggingFaceFile(f.Url, revision));
            var previous = !options.Force && immutable && TextClassification.Classifier is null ? Load(resultPath) : null;
            if (previous is { Completed: true } && previous.Scanner == scanner &&
                (!options.KeepDownloads || previous.Reports.Where(r => r.Kind != "download").All(r => r.Path is not null && File.Exists(r.Path))) &&
                previous.Files.Sum(f => f.Size) < options.MaxBytes)
            {
                progress?.Invoke($"Reusing saved scan: {job.Id}");
                foreach (var report in previous.Reports) yield return report;
                continue;
            }
            if (_downloaded >= options.MaxTotalBytes || knownSize is { } size && size > options.MaxTotalBytes - _downloaded)
            {
                yield return Failure(job.Id, "Run download budget would be exceeded. Rerun to continue, or raise --max-total-gb.");
                yield break;
            }

            var downloadDir = Path.Combine(root, "downloads", key + "-" + Guid.NewGuid().ToString("N"));
            var receipts = new List<DownloadReceipt>();
            var reports = new List<ScanReport>();
            try
            {
                progress?.Invoke($"Downloading and scanning {job.Id} ({job.Files.Count} file(s))");
                System.IO.Directory.CreateDirectory(downloadDir);
                long jobBytes = 0;
                foreach (var file in job.Files)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var destination = Path.Combine(downloadDir, file.Path.Replace('/', Path.DirectorySeparatorChar));
                    System.IO.Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                    var receipt = Download(file, destination, options.MaxBytes - jobBytes - 1,
                        options.MaxTotalBytes, cancellationToken).GetAwaiter().GetResult();
                    receipts.Add(receipt);
                    jobBytes = checked(jobBytes + receipt.Size);
                }
                foreach (var file in job.Files.Where(f => ModelScanner.IsScannable(f.Path)))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var path = Path.Combine(downloadDir, file.Path.Replace('/', Path.DirectorySeparatorChar));
                    reports.Add(Retarget(ModelScanner.ScanAnyFile(path), job.Id + "/" + file.Path, options.KeepDownloads));
                }
                var auxiliary = job.Files.Count(f => !ModelScanner.IsScannable(f.Path));
                if (auxiliary > 0)
                    reports.Add(Notice(job.Id, "Companion files downloaded", $"{auxiliary} companion file(s) downloaded for model context. Their formats have no standalone scanner."));
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or
                HttpRequestException or OperationCanceledException or JsonException)
            {
                // Do not print exception URLs: signed query strings can contain credentials.
                reports.Add(Failure(job.Id, SafeError(ex)));
            }
            finally
            {
                if (!options.KeepDownloads && System.IO.Directory.Exists(downloadDir))
                {
                    try { System.IO.Directory.Delete(downloadDir, recursive: true); }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        reports.Add(Failure(job.Id, "Could not remove this run's download directory: " + downloadDir));
                    }
                }
            }
            var completed = reports.Count > 0 && reports.All(r => r.Error is null);
            Save(resultPath, new BatchResult(job.Id, job.Revision, scanner, DateTimeOffset.UtcNow,
                completed, receipts, reports));
            foreach (var report in reports) yield return report;
            cancellationToken.ThrowIfCancellationRequested();
            if (_downloaded > options.MaxTotalBytes) yield break;
        }
    }

    async Task<DownloadReceipt> Download(DownloadFile file, string path, long remainingModelBytes,
        long totalLimit, CancellationToken cancellationToken)
    {
        var uri = DownloadPlan.ValidateUrl(file.Url);
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        if (file.TokenEnvironment is { } variable)
        {
            if (uri.Scheme != "https") throw new InvalidDataException("Bearer authentication requires HTTPS.");
            var token = Environment.GetEnvironmentVariable(variable);
            if (string.IsNullOrEmpty(token)) throw new InvalidDataException("The requested bearer token environment variable is empty.");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new InvalidDataException($"Download returned HTTP {(int)response.StatusCode} for {file.Path}.");
        if (response.StatusCode == System.Net.HttpStatusCode.PartialContent || response.Content.Headers.ContentEncoding.Count > 0)
            throw new InvalidDataException("Expected a complete, unencoded download response.");
        var expected = response.Content.Headers.ContentLength;
        if (file.Size is { } declared && expected is { } actual && declared != actual)
            throw new InvalidDataException($"Published and downloaded sizes disagree for {file.Path}.");
        if ((expected ?? file.Size) is { } length &&
            (length > remainingModelBytes || length > totalLimit - _downloaded))
            throw new InvalidDataException("Download would exceed the model or run byte limit.");
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 20, true);
        var buffer = new byte[1 << 20];
        long written = 0;
        while (true)
        {
            using var idle = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            idle.CancelAfter(TimeSpan.FromSeconds(60));
            // One lookahead byte detects a dishonest/chunked response at the exact boundary.
            var available = Math.Min(remainingModelBytes - written, totalLimit - _downloaded);
            var count = (int)Math.Min(buffer.Length, available + 1);
            if (count <= 0) throw new InvalidDataException("Download byte budget exhausted.");
            var read = await input.ReadAsync(buffer.AsMemory(0, count), idle.Token).ConfigureAwait(false);
            if (read == 0) break;
            _downloaded = checked(_downloaded + read);
            if (read > available) throw new InvalidDataException("Streaming download exceeded the model or run byte limit.");
            digest.AppendData(buffer, 0, read);
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            written += read;
        }
        if (expected is { } contentSize && written != contentSize || file.Size is { } manifestSize && written != manifestSize)
            throw new InvalidDataException("Truncated download or incorrect published size.");
        var sha = Convert.ToHexStringLower(digest.GetHashAndReset());
        if (file.Sha256 is { } expectedSha && !sha.Equals(expectedSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"SHA-256 mismatch for {file.Path}.");
        return new DownloadReceipt(file.Path, DownloadPlan.DisplayUrl(file.Url), written, sha);
    }

    static bool IsPinnedHuggingFaceFile(string url, string revision)
    {
        var uri = DownloadPlan.ValidateUrl(url);
        return uri.Scheme == "https" && uri.Host == "huggingface.co" && uri.IsDefaultPort &&
            uri.AbsolutePath.Contains("/resolve/" + revision + "/", StringComparison.Ordinal);
    }

    static ScanReport Retarget(ScanReport source, string target, bool keep)
    {
        var report = new ScanReport { Target = target, Kind = source.Kind, Path = keep ? source.Path : null,
            Fingerprint = source.Fingerprint, Summary = source.Summary, Error = source.Error };
        report.Findings.AddRange(source.Findings);
        report.Templates.AddRange(source.Templates);
        foreach (var hash in source.ContentHashes) report.ContentHashes[hash.Key] = hash.Value;
        return report;
    }

    static string SafeError(Exception ex) => ex switch
    {
        OperationCanceledException => "Download cancelled or timed out; this job remains incomplete.",
        HttpRequestException => "Network request failed; this job remains incomplete.",
        _ => ex.Message,
    };

    static ScanReport Notice(string target, string title, string detail)
    {
        var report = new ScanReport { Target = target, Kind = "download" };
        report.Findings.Add(new Finding("D001", Severity.Info, title, detail, "download"));
        return report;
    }

    public static ScanReport Failure(string target, string error) => new() { Target = target, Kind = "download", Error = error };

    static BatchResult? Load(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            return JsonSerializer.Deserialize(stream, BatchJsonContext.Default.BatchResult);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { return null; }
    }

    static void Save(string path, BatchResult result)
    {
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write))
            {
                JsonSerializer.Serialize(stream, result, BatchJsonContext.Default.BatchResult);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public void Dispose() => _http.Dispose();
}
