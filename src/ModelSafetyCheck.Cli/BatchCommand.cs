using System.CommandLine;
using System.Text.Json;
using ModelSafetyCheck.Hub;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Cli;

static class BatchCommand
{
    public static Command Create()
    {
        var sources = new Argument<string[]>("sources")
        {
            Description = "Direct HTTP(S) file URLs or hf:org/repo. Use a manifest for arbitrary download endpoints and multi-file models.",
            Arity = ArgumentArity.ZeroOrMore,
        };
        var manifest = new Option<string?>("--manifest") { Description = "Local JSON manifest of provider-neutral model file sets." };
        var discover = new Option<bool>("--discover-hf") { Description = "Discover Hugging Face models by text task (paginated, most downloaded first)." };
        var tasks = new Option<string[]>("--task") { Description = "Hugging Face pipeline tag. Repeat for multiple tasks; default: all supported text tasks." };
        var limit = new Option<int>("--limit") { Description = "Maximum unique repositories to discover; 0 enumerates all matches.", DefaultValueFactory = _ => 100 };
        var directory = new Option<string>("--directory") { Description = "Batch results and isolated download directories.", DefaultValueFactory = _ => "modelcheck-batch" };
        var maxGb = new Option<decimal>("--max-gb") { Description = "Strict per-model limit in decimal GB, including every shard and companion file.", DefaultValueFactory = _ => 100m };
        var totalGb = new Option<decimal>("--max-total-gb") { Description = "Download budget per invocation in decimal GB.", DefaultValueFactory = _ => 1000m };
        var keep = new Option<bool>("--keep-downloads") { Description = "Retain downloaded files after scanning; default removes this job's downloads and retains reports." };
        var dry = new Option<bool>("--dry-run") { Description = "Discover and show file-set sizes without downloading model files or writing batch state." };
        var force = new Option<bool>("--force") { Description = "Rescan even if an unchanged immutable model has a completed report." };
        var variant = new Option<string>("--variant") { Description = "Hugging Face variants per repository: all, or only the smallest set below --max-gb.", DefaultValueFactory = _ => "all" };
        variant.AcceptOnlyFromAmong("all", "smallest");
        var writeManifest = new Option<string?>("--write-manifest") { Description = "Write the pinned file sets (commits, sizes, sha256) to a manifest instead of scanning, so later runs and other machines work through the same list." };
        var command = new Command("batch", "Download and statically scan model file sets from Hugging Face or arbitrary HTTP(S) providers, with bounded downloads and saved results.")
        {
            sources, manifest, discover, tasks, limit, directory, maxGb, totalGb, keep, dry, force, variant, writeManifest,
        };
        command.SetAction(parse =>
        {
            using var cancel = new CancellationTokenSource();
            ConsoleCancelEventHandler onCancel = (_, e) => { e.Cancel = true; cancel.Cancel(); };
            Console.CancelKeyPress += onCancel;
            try
            {
                var inputs = parse.GetValue(sources) ?? [];
                if (inputs.Length == 0 && parse.GetValue(manifest) is null && !parse.GetValue(discover))
                    throw new InvalidDataException("Supply a URL, hf:org/repo, --manifest, or --discover-hf.");
                var repoLimit = parse.GetValue(limit);
                if (repoLimit < 0) throw new InvalidDataException("--limit must be nonnegative.");
                var maxBytes = Bytes(parse.GetValue(maxGb));
                var totalBytes = Bytes(parse.GetValue(totalGb));
                var options = new BatchOptions(parse.GetValue(directory)!, maxBytes, totalBytes,
                    parse.GetValue(keep), parse.GetValue(dry), parse.GetValue(force));
                var smallest = parse.GetValue(variant) == "smallest";
                if (parse.GetValue(writeManifest) is { } output)
                    return WriteManifest(output, inputs, parse.GetValue(manifest), parse.GetValue(discover),
                        parse.GetValue(tasks) ?? [], repoLimit, smallest, maxBytes, cancel.Token);
                return Program.Run(parse, Reports(inputs, parse.GetValue(manifest), parse.GetValue(discover),
                    parse.GetValue(tasks) ?? [], repoLimit, smallest, options, cancel.Token));
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or
                JsonException or HttpRequestException or OperationCanceledException or OverflowException or ArgumentException)
            {
                Console.Error.WriteLine(ex is HttpRequestException ? "Network request failed." : ex.Message);
                return Program.ExitError;
            }
            finally { Console.CancelKeyPress -= onCancel; }
        });
        return command;
    }

    static long Bytes(decimal gb)
    {
        var bytes = checked((long)(gb * 1_000_000_000m));
        return bytes > 0 ? bytes : throw new InvalidDataException("GB limits must be positive.");
    }

    /// <summary>
    /// Resolves the sources to pinned file sets and writes them as a manifest. Scanning that manifest gives every run, on
    /// any machine, the same list and the same result keys, however the Hub's rankings or repositories change meanwhile.
    /// </summary>
    static int WriteManifest(string path, string[] sources, string? manifest, bool discover, string[] tasks, int limit,
        bool smallest, long maxBytes, CancellationToken cancellationToken)
    {
        using var hub = new HuggingFaceClient();
        var errors = new Queue<ScanReport>();
        var models = new List<DownloadJob>();
        foreach (var job in Jobs(hub, sources, manifest, discover, tasks, limit, smallest, maxBytes, errors, cancellationToken))
        {
            if (job.Error is not null)
                Console.Error.WriteLine($"Left out {job.Id}: {job.Error}");
            else if (job.Files.All(f => f.Size is not null) && job.Files.Sum(f => f.Size!.Value) >= maxBytes)
                Console.Error.WriteLine($"Left out {job.Id}: {job.Files.Sum(f => f.Size!.Value):N0} bytes meets or exceeds the per-model limit.");
            else
                models.Add(job);
        }
        while (errors.TryDequeue(out var error)) Console.Error.WriteLine($"{error.Target}: {error.Error}");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        File.WriteAllText(path, JsonSerializer.Serialize(new DownloadManifest(models), BatchJsonContext.Default.DownloadManifest) + "\n");
        var bytes = models.SelectMany(m => m.Files).Sum(f => f.Size ?? 0);
        Console.Error.WriteLine($"Wrote {models.Count} model file set(s), {bytes:N0} bytes, to {path}.");
        return Program.ExitClean;
    }

    static IEnumerable<ScanReport> Reports(string[] sources, string? manifest, bool discover, string[] tasks,
        int limit, bool smallest, BatchOptions options, CancellationToken cancellationToken)
    {
        using var hub = new HuggingFaceClient();
        using var scanner = new BatchScanner();
        var errors = new Queue<ScanReport>();
        // Keep discovery lazy so a large Hub crawl can checkpoint completed models as it progresses.
        var jobs = Jobs(hub, sources, manifest, discover, tasks, limit, smallest, options.MaxBytes, errors, cancellationToken);
        foreach (var report in scanner.Scan(jobs, options, Console.Error.WriteLine, cancellationToken))
        {
            while (errors.TryDequeue(out var error)) yield return error;
            yield return report;
        }
        while (errors.TryDequeue(out var error)) yield return error;
    }

    static IEnumerable<DownloadJob> Jobs(HuggingFaceClient hub, string[] sources, string? manifest,
        bool discover, string[] tasks, int limit, bool smallest, long maxBytes, Queue<ScanReport> errors,
        CancellationToken cancellationToken)
    {
        if (manifest is not null)
            foreach (var job in DownloadPlan.ReadManifest(manifest).Models) yield return job;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var source in sources.Concat(discover ? Discover(hub, tasks, limit, errors, cancellationToken) : []))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var isHf = source.StartsWith("hf:", StringComparison.OrdinalIgnoreCase);
            if (!isHf)
            {
                DownloadJob? job = null;
                try { job = DownloadPlan.FromUrl(source); }
                catch (Exception ex) when (ex is InvalidDataException or ArgumentException)
                {
                    job = new DownloadJob("URL source", [], Error: ex.Message);
                }
                if (job is not null) yield return job;
                continue;
            }
            var repo = HuggingFaceClient.NormalizeRepoId(source);
            if (repo is null)
            {
                yield return new DownloadJob("Hugging Face source", [], Error: "Invalid hf:org/repo identifier.");
                continue;
            }
            if (!seen.Add(repo)) continue;
            var jobs = HuggingFaceJobs(hub, repo);
            foreach (var job in smallest ? DownloadPlan.SmallestModel(jobs, maxBytes) : jobs) yield return job;
        }
    }

    static IEnumerable<DownloadJob> HuggingFaceJobs(HuggingFaceClient hub, string repo)
    {
        using var iterator = DownloadPlan.FromHuggingFace(hub, repo).GetEnumerator();
        while (true)
        {
            DownloadJob? job;
            var failed = false;
            try { if (!iterator.MoveNext()) break; job = iterator.Current; }
            catch (Exception ex) when (ex is IOException or InvalidDataException or HttpRequestException or
                OperationCanceledException or JsonException or OverflowException)
            {
                job = new DownloadJob("hf:" + repo, [], Error:
                    ex is HttpRequestException ? "Hugging Face request failed." : ex.Message);
                failed = true;
            }
            yield return job;
            if (failed) break;
        }
    }

    static IEnumerable<string> Discover(HuggingFaceClient hub, string[] tasks, int limit,
        Queue<ScanReport> errors, CancellationToken cancellationToken)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var task in tasks.Length == 0 ? DownloadPlan.TextTasks : tasks)
        {
            using var iterator = hub.ListModels(task).GetEnumerator();
            while (limit == 0 || seen.Count < limit)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string repo;
                try { if (!iterator.MoveNext()) break; repo = iterator.Current; }
                catch (Exception ex) when (ex is IOException or HttpRequestException or OperationCanceledException or JsonException)
                {
                    errors.Enqueue(BatchScanner.Failure("hf-discovery:" + task, "Task discovery failed; coverage is incomplete."));
                    break;
                }
                if (seen.Add(repo)) yield return "hf:" + repo;
            }
            if (limit != 0 && seen.Count >= limit) yield break;
        }
    }
}
