using System.CommandLine;
using System.Net.Http.Headers;
using Downloader;
using ModelSafetyCheck.Hub;

namespace ModelSafetyCheck.Cli;

/// <summary>
/// `modelcheck download`: resumable, multi-connection download of one model file (from the Downloader library), checked
/// against the size and sha256 Hugging Face publishes, and optionally scanned. Rerunning an interrupted command resumes.
/// </summary>
public static class DownloadCommand
{
    public static Command Create()
    {
        var source = new Argument<string>("source") { Description = "hf:org/name/path/file.gguf, or an http(s) URL." };
        var output = new Option<string>("--out", "-o") { Description = "Directory to save into.", DefaultValueFactory = _ => "." };
        var connections = new Option<int>("--connections", "-c") { Description = "Parallel connections.", DefaultValueFactory = _ => 4 };
        var sha = new Option<string?>("--sha256") { Description = "Expected sha256 (Hugging Face files use the published one automatically)." };
        var scan = new Option<bool>("--scan") { Description = "Scan the file after downloading." };
        var command = new Command("download", "Download a model file with resume, several connections and sha256 verification. Rerun to resume.")
        {
            source, output, connections, sha, scan,
        };
        command.SetAction(async (result, cancellationToken) =>
        {
            var path = await Run(result.GetValue(source)!, result.GetValue(output)!, result.GetValue(connections),
                result.GetValue(sha), cancellationToken);
            if (path is null) return Program.ExitError;
            return result.GetValue(scan) ? Program.Run(result, Program.ScanPaths([path])) : Program.ExitClean;
        });
        return command;
    }

    /// <summary>Downloads <paramref name="source"/>; returns the saved path, or null after printing why it failed.</summary>
    public static async Task<string?> Run(string source, string directory, int connections, string? sha256, CancellationToken cancellationToken)
    {
        if (connections is < 1 or > 32)
        {
            Console.Error.WriteLine("--connections must be 1 to 32.");
            return null;
        }
        Uri url;
        long? size = null;
        if (source.StartsWith("hf:", StringComparison.Ordinal))
        {
            var parts = source[3..].Split('/', 3);
            if (parts.Length < 3 || HuggingFaceClient.NormalizeRepoId(parts[0] + "/" + parts[1]) is not { } repo)
            {
                Console.Error.WriteLine("Expected hf:org/name/path/to/file.");
                return null;
            }
            try
            {
                using var hub = new HuggingFaceClient();
                var info = hub.GetModel(repo);
                if (info.Files.FirstOrDefault(f => f.Path == parts[2]) is not { } file)
                {
                    Console.Error.WriteLine($"{repo} has no file {parts[2]}.");
                    return null;
                }
                // Pin to the commit just read, so the published size and sha256 describe the bytes downloaded.
                url = hub.FileUrl(repo, file.Path, info.Revision ?? "main");
                size = file.Size;
                sha256 ??= file.Sha256;
            }
            catch (Exception ex) when (ex is HttpRequestException or InvalidDataException or IOException)
            {
                Console.Error.WriteLine($"Could not read {repo}: {ex.Message}");
                return null;
            }
        }
        else if (!Uri.TryCreate(source, UriKind.Absolute, out url!) || url.Scheme is not ("https" or "http"))
        {
            Console.Error.WriteLine("Expected hf:org/name/path/file or an http(s) URL.");
            return null;
        }

        var name = Uri.UnescapeDataString(url.Segments[^1]);
        if (name.Length == 0 || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) name = "download";
        var destination = Path.GetFullPath(Path.Combine(directory, name));
        if (File.Exists(destination))
        {
            Console.Error.WriteLine($"{destination} already exists.");
            return null;
        }
        var token = Environment.GetEnvironmentVariable("HF_TOKEN");
        var request = new DownloadRequest(url, destination)
        {
            Connections = connections,
            ExpectedSize = size,
            ExpectedSha256 = sha256,
            Authorization = url is { Scheme: "https", Host: "huggingface.co" } && !string.IsNullOrEmpty(token) ? new AuthenticationHeaderValue("Bearer", token) : null,
        };
        using var downloader = new SegmentedDownloader();
        try
        {
            var result = await downloader.DownloadAsync(request, new Progress<DownloadProgress>(p => Show(name, p)), cancellationToken);
            Console.Error.WriteLine();
            Console.Error.WriteLine($"Saved {result.Path} ({result.Size:N0} bytes, sha256 {result.Sha256}" +
                (sha256 is null ? ", not checked against a published hash" : ", verified") +
                (result.ResumedBytes > 0 ? $", resumed from {result.ResumedBytes:N0} bytes" : "") + ")");
            return result.Path;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine("Paused. Run the same command again to resume.");
        }
        catch (Exception ex) when (ex is DownloadException or HttpRequestException or IOException or TimeoutException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine($"Download failed: {ex.Message}");
            if (ex is not DownloadException) Console.Error.WriteLine("Progress is saved; run the same command again to resume.");
        }
        return null;
    }

    static DateTime _lastDraw;

    static void Show(string name, DownloadProgress p)
    {
        if (DateTime.UtcNow - _lastDraw < TimeSpan.FromMilliseconds(250) && p.Received != p.Total) return;
        _lastDraw = DateTime.UtcNow;
        const double GiB = 1 << 30, MiB = 1 << 20;
        var line = p.Total is { } total and > 0
            ? $"{name}  {100.0 * p.Received / total,5:F1}%  {p.Received / GiB:F2}/{total / GiB:F2} GiB  {p.BytesPerSecond / MiB,6:F1} MiB/s  {p.Connections} conn"
            : $"{name}  {p.Received / MiB:F1} MiB  {p.BytesPerSecond / MiB:F1} MiB/s";
        Console.Error.Write("\r" + line.PadRight(Math.Min(120, Console.IsErrorRedirected ? 0 : Console.BufferWidth - 1)));
    }
}
