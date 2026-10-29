using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Rules.Lineage;

/// <summary>Reads <c>count</c> bytes at an absolute file offset.</summary>
public delegate byte[] RangeReader(long offset, int count);

/// <summary>A GGUF whose header has been parsed, plus a way to read slices of its tensor data.</summary>
public sealed record LineageInput(string Name, GgufFile File, RangeReader Read)
{
    /// <summary>Reads through a seekable stream (one read at a time).</summary>
    public static LineageInput FromStream(string name, Stream stream)
    {
        var file = GgufParser.Parse(stream);
        var gate = new Lock();
        return new LineageInput(name, file, (offset, count) =>
        {
            var buffer = new byte[count];
            lock (gate)
            {
                stream.Position = offset;
                stream.ReadExactly(buffer);
            }
            return buffer;
        });
    }

    /// <summary>Reads a local file with positional reads, safe to use in parallel.</summary>
    public static LineageInput FromFile(string path, FileStream stream)
    {
        var file = GgufParser.Parse(stream);
        var handle = stream.SafeFileHandle;
        return new LineageInput(path, file, (offset, count) =>
        {
            var buffer = new byte[count];
            var read = 0;
            while (read < count)
            {
                var n = RandomAccess.Read(handle, buffer.AsSpan(read), offset + read);
                if (n <= 0) throw new EndOfStreamException();
                read += n;
            }
            return buffer;
        });
    }
}

public sealed record LineageOptions
{
    /// <summary>Values compared per tensor: whole rows from the middle of the tensor, at least one row.</summary>
    public int SampleValues { get; init; } = 16384;

    /// <summary>A tensor whose normalized error is above this is "modified". Genuine quants measure about 0.29 (uniform rounding).</summary>
    public double ModifiedThreshold { get; init; } = 0.6;

    /// <summary>Tensors compared at once (remote reads are latency-bound).</summary>
    public int Parallelism { get; init; } = 8;

    /// <summary>Optional progress callback (tensors done, total).</summary>
    public Action<int, int>? Progress { get; init; }
}

/// <summary>
/// One tensor compared. <see cref="NormalizedError"/> is the RMS of (candidate - base) divided by the quantization step at
/// each value (both files' steps, in quadrature). Rounding to the nearest level gives about 0.29 whatever the GGML type,
/// so a quantization of these exact weights stays near that, while changed weights push it far above.
/// </summary>
public sealed record TensorComparison(
    string Name, string CandidateType, string BaseType, long Elements, int Sampled,
    double RelativeError, double Cosine, double NormalizedError, double OutOfStep, bool Modified, string? Skipped = null)
{
    /// <summary>
    /// For a 2-D tensor that differs: the normalized error left after fitting a scale per row and per column
    /// (c ≈ r_i·s_j·b). Conversions that migrate scales between a norm and the next matrix (AWQ, as in Qwen's official
    /// GGUFs) are explained by this; fine-tunes, merges and abliteration are not. NaN when not computed.
    /// </summary>
    public double RescaledError { get; init; } = double.NaN;

    /// <summary>Differs from the base, but only by per-channel rescaling.</summary>
    public bool Rescaled { get; init; }

    public string Layer => LayerOf(Name);

    internal static string LayerOf(string name)
    {
        var m = Regex.Match(name, @"^blk\.(\d+)\.");
        return m.Success ? $"blk.{m.Groups[1].Value}" : "other";
    }
}

public enum LineageVerdict { Match, Rescaled, Modified, Unrelated, Inconclusive }

public sealed class LineageResult
{
    public required string Candidate { get; init; }
    public required string Base { get; init; }
    public List<TensorComparison> Tensors { get; } = [];
    public List<string> OnlyInCandidate { get; } = [];
    public List<string> OnlyInBase { get; } = [];
    public List<string> ShapeMismatch { get; } = [];

    public IEnumerable<TensorComparison> Compared => Tensors.Where(t => t.Skipped is null);

    public bool SystematicRescaling => Compared.Count(t => t.Rescaled) * 4 >= Math.Max(1, Compared.Count());

    /// <summary>Tensors counted as changed: those rescaling does not explain, plus isolated rescaled ones.</summary>
    public IEnumerable<TensorComparison> Changed => Compared.Where(t => t.Modified || (t.Rescaled && !SystematicRescaling));

    public LineageVerdict Verdict
    {
        get
        {
            var compared = Compared.ToList();
            if (compared.Count == 0) return LineageVerdict.Inconclusive;
            // Most tensors essentially uncorrelated: a different model, not a modified one.
            if (compared.Count(t => t.Cosine < 0.5) * 2 > compared.Count || ShapeMismatch.Count * 2 > compared.Count + ShapeMismatch.Count)
                return LineageVerdict.Unrelated;
            // Systematic rescaling (a quarter of the tensors or more) means one file went through an activation-aware conversion
            // (AWQ scale migration and clipping). Its clipping is as large as small edits, so no verdict either way is safe.
            if (SystematicRescaling) return LineageVerdict.Rescaled;
            // A few rescaled tensors without the pattern are an edit like any other.
            return compared.Any(t => t.Modified || t.Rescaled) || ShapeMismatch.Count > 0 || OnlyInCandidate.Count > 0
                ? LineageVerdict.Modified : LineageVerdict.Match;
        }
    }
}

/// <summary>
/// Checks whether a GGUF that claims to be a quantization of a base model really carries the base's weights:
/// dequantizes the same rows of every shared tensor in both files and compares them against the quantization noise.
/// A match proves the weights are the base's (up to quantization). A mismatch shows modification (fine-tune, merge,
/// abliteration), not malice.
/// </summary>
public static class WeightLineage
{
    public static LineageResult Compare(LineageInput candidate, LineageInput @base, LineageOptions? options = null)
    {
        options ??= new LineageOptions();
        var result = new LineageResult { Candidate = candidate.Name, Base = @base.Name };
        var baseTensors = @base.File.Tensors.GroupBy(t => t.Name).ToDictionary(g => g.Key, g => g.First());
        var candidateNames = candidate.File.Tensors.Select(t => t.Name).ToHashSet();
        result.OnlyInBase.AddRange(@base.File.Tensors.Select(t => t.Name).Where(n => !candidateNames.Contains(n)).Distinct());

        var tensors = candidate.File.Tensors.DistinctBy(t => t.Name).ToList();
        var pairs = new List<(GgufTensorInfo C, GgufTensorInfo B)>();
        foreach (var c in tensors)
        {
            // Tied embeddings: some converters write output.weight as a copy of token_embd.weight, others leave it out.
            if (!baseTensors.TryGetValue(c.Name, out var b) && c.Name == "output.weight" && baseTensors.TryGetValue("token_embd.weight", out var tied))
                b = tied;
            if (b is null)
                result.OnlyInCandidate.Add(c.Name);
            else if (!c.Dimensions.SequenceEqual(b.Dimensions))
                result.ShapeMismatch.Add($"{c.Name}: [{string.Join(", ", c.Dimensions)}] vs [{string.Join(", ", b.Dimensions)}]");
            else
                pairs.Add((c, b));
        }

        var compared = new TensorComparison[pairs.Count];
        var done = 0;
        Exception? failure = null;
        Parallel.For(0, pairs.Count, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, options.Parallelism) }, (i, state) =>
        {
            try
            {
                compared[i] = CompareTensor(candidate, pairs[i].C, @base, pairs[i].B, options);
            }
            catch (Exception ex)
            {
                failure ??= ex;
                state.Stop();
                return;
            }
            options.Progress?.Invoke(Interlocked.Increment(ref done), pairs.Count);
        });
        if (failure is not null)
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw(failure);
        // Scale migration also changes the vectors it moves the scale out of (norm weights, some biases). They cannot be
        // fitted on their own, so a differing 1-D tensor counts as rescaled when its layer's matrices were rescaled.
        var rescaledLayers = compared.Where(t => t.Rescaled).Select(t => t.Layer).ToHashSet();
        for (var i = 0; i < compared.Length; i++)
            if (compared[i].Modified && pairs[i].C.Dimensions.Length == 1 && rescaledLayers.Contains(compared[i].Layer))
                compared[i] = compared[i] with { Modified = false, Rescaled = true };
        result.Tensors.AddRange(compared);
        return result;
    }

    static TensorComparison CompareTensor(LineageInput candidate, GgufTensorInfo c, LineageInput @base, GgufTensorInfo b, LineageOptions options)
    {
        var elements = c.Dimensions.Aggregate(1L, (a, d) => checked(a * (long)d));
        TensorComparison Skip(string why) => new(c.Name, GgmlTypes.NameOf(c.Type), GgmlTypes.NameOf(b.Type), elements, 0, 0, 0, 0, 0, false, why);

        foreach (var t in new[] { c.Type, b.Type })
            if (!GgmlDequant.IsSupported(t))
                return Skip($"{GgmlTypes.NameOf(t)} is not supported yet");
        if (c.Dimensions.Length == 0 || elements == 0)
            return Skip("empty tensor");

        var rowLength = (long)c.Dimensions[0];
        var rows = elements / rowLength;
        // At least 4 rows of a matrix, so per-column scales can be fitted.
        var sampleRows = (int)Math.Min(rows, Math.Max(4, (options.SampleValues + rowLength - 1) / rowLength));
        var firstRow = (rows - sampleRows) / 2;
        var count = checked((int)(sampleRows * rowLength));

        float[] cv, cs, bv, bs;
        try
        {
            (cv, cs) = ReadRows(candidate, c, firstRow, count, rowLength);
            (bv, bs) = ReadRows(@base, b, firstRow, count, rowLength);
        }
        catch (ArgumentException ex)
        {
            return Skip(ex.Message);
        }

        double dot = 0, bb = 0, cc = 0, dd = 0;
        for (var i = 0; i < count; i++)
        {
            dot += (double)cv[i] * bv[i];
            bb += (double)bv[i] * bv[i];
            cc += (double)cv[i] * cv[i];
            var d = (double)cv[i] - bv[i];
            dd += d * d;
        }
        // A floor for the step, so exact zeros in float formats do not divide by zero.
        var floor = 1e-6 * Math.Sqrt(bb / count) + 1e-12;
        double norm = 0;
        var outside = 0;
        for (var i = 0; i < count; i++)
        {
            var step = Math.Sqrt((double)cs[i] * cs[i] + (double)bs[i] * bs[i]) + floor;
            var d = Math.Abs((double)cv[i] - bv[i]);
            var e = d / step;
            norm += e * e;
            // Nearest rounding leaves each value within half a step of the original (fp16 scales add a little).
            if (d > 0.5 * (cs[i] + bs[i]) + Math.Abs(cv[i]) / 1024 + floor) outside++;
        }
        var relative = bb > 0 ? Math.Sqrt(dd / bb) : Math.Sqrt(dd);
        var cosine = bb > 0 && cc > 0 ? dot / Math.Sqrt(bb * cc) : dd == 0 ? 1 : 0;
        var normalized = Math.Sqrt(norm / count);
        var differs = normalized > options.ModifiedThreshold;
        var rescaled = differs && sampleRows >= 4 ? RescaledError(cv, cs, bv, bs, sampleRows, (int)rowLength, floor) : double.NaN;
        var explained = rescaled <= options.ModifiedThreshold;
        return new TensorComparison(c.Name, GgmlTypes.NameOf(c.Type), GgmlTypes.NameOf(b.Type), elements, count,
            relative, cosine, normalized, (double)outside / count, differs && !explained)
        {
            RescaledError = rescaled,
            Rescaled = differs && explained,
        };
    }

    /// <summary>
    /// Fits c ≈ r_i·s_j·b (row and column scales, alternating least squares) and returns the normalized error of what is
    /// left. Uses a robust (median-based) RMS so the few weights AWQ clips do not hide that the rest is only rescaled.
    /// </summary>
    static double RescaledError(float[] c, float[] cs, float[] b, float[] bs, int rows, int cols, double floor)
    {
        var r = new double[rows];
        var s = new double[cols];
        Array.Fill(r, 1.0);
        Array.Fill(s, 1.0);
        for (var iteration = 0; iteration < 4; iteration++)
        {
            for (var j = 0; j < cols; j++)
            {
                double num = 0, den = 0;
                for (var i = 0; i < rows; i++)
                {
                    var x = r[i] * b[i * cols + j];
                    num += x * c[i * cols + j];
                    den += x * x;
                }
                s[j] = den > 0 ? num / den : 1;
            }
            for (var i = 0; i < rows; i++)
            {
                double num = 0, den = 0;
                for (var j = 0; j < cols; j++)
                {
                    var x = s[j] * b[i * cols + j];
                    num += x * c[i * cols + j];
                    den += x * x;
                }
                r[i] = den > 0 ? num / den : 1;
            }
        }
        var squared = new double[rows * cols];
        for (var i = 0; i < rows; i++)
            for (var j = 0; j < cols; j++)
            {
                var k = i * cols + j;
                var scale = Math.Abs(r[i] * s[j]);
                var step = Math.Sqrt((double)cs[k] * cs[k] + scale * scale * bs[k] * bs[k]) + floor;
                var e = (c[k] - r[i] * s[j] * b[k]) / step;
                squared[k] = e * e;
            }
        // Trim the largest 2% (clipped outliers), then rescale so uniform rounding still measures about 0.29.
        Array.Sort(squared);
        var keep = Math.Max(1, (int)(squared.Length * 0.98));
        double sum = 0;
        for (var k = 0; k < keep; k++) sum += squared[k];
        return Math.Sqrt(sum / keep) * 1.03;
    }

    static (float[] Values, float[] Steps) ReadRows(LineageInput input, GgufTensorInfo t, long firstRow, int count, long rowLength)
    {
        var rowBytes = GgmlDequant.ByteCount(t.Type, rowLength);
        var offset = input.File.DataStart + (long)t.Offset + firstRow * rowBytes;
        var length = GgmlDequant.ByteCount(t.Type, count);
        if (offset < 0 || offset + length > input.File.FileLength)
            throw new ArgumentException("tensor data lies outside the file");
        var data = input.Read(offset, checked((int)length));
        var values = new float[count];
        var steps = new float[count];
        GgmlDequant.Dequantize(t.Type, data, values, steps);
        return (values, steps);
    }

    /// <summary>Findings: L001 modified, L002 unrelated, L003 match, L004 tensors not compared.</summary>
    public static ScanReport ToReport(LineageResult r, string? claim = null)
    {
        var report = new ScanReport { Target = r.Candidate, Kind = "lineage" };
        var compared = r.Compared.ToList();
        var table = Table(r);
        var claimText = claim is null ? $"the base {r.Base}" : $"{claim} ({r.Base})";
        var stats = compared.Count == 0 ? "" :
            $"Compared {compared.Count} tensors ({compared.Sum(t => (long)t.Sampled):N0} values sampled). Normalized error: median {Median(compared.Select(t => t.NormalizedError)):0.00}, " +
            $"max {compared.Max(t => t.NormalizedError):0.00} (a quantization of the same weights measures about 0.29; above {new LineageOptions().ModifiedThreshold:0.0} counts as changed).";

        switch (r.Verdict)
        {
            case LineageVerdict.Match:
                report.Findings.Add(new Finding("L003", Severity.Info, "Weights match the base model within quantization noise",
                    $"Every compared tensor is what quantizing {claimText} would give. {stats}\n{table}", "weights"));
                break;
            case LineageVerdict.Rescaled:
                var rescaled = compared.Count(t => t.Rescaled);
                var unexplained = compared.Where(t => t.Modified).OrderByDescending(t => t.RescaledError).ToList();
                report.Findings.Add(new Finding("L005", Severity.Medium, "Lineage inconclusive: one file is an activation-aware (AWQ-style) conversion",
                    $"{rescaled} of {compared.Count} tensors differ from {claimText} by per-channel scales, the pattern of AWQ scale migration " +
                    "(Qwen's official GGUFs are made this way). That conversion also clips outlier weights, which changes them about as much as a light fine-tune or " +
                    $"abliteration would, so this comparison can neither prove the weights genuine nor show them modified" +
                    (unexplained.Count > 0 ? $" ({unexplained.Count} tensors are not explained by rescaling alone, e.g. {string.Join(", ", unexplained.Take(5).Select(t => t.Name))})" : "") +
                    ". Compare against a direct F16/BF16/Q8_0 conversion of the published safetensors instead (for example the one from a quantizer that converts directly, or your own convert_hf_to_gguf.py output). " +
                    $"{stats}\n{table}", "weights"));
                break;
            case LineageVerdict.Unrelated:
                report.Findings.Add(new Finding("L002", Severity.High, "Weights are not derived from the claimed base model",
                    $"Most tensors are uncorrelated with {claimText}{(r.ShapeMismatch.Count > 0 ? $" or have different shapes ({r.ShapeMismatch.Count})" : "")}: this is a different model, " +
                    $"not a quantization or a fine-tune of it. {stats}\n{table}", "weights"));
                break;
            case LineageVerdict.Modified:
                var changed = r.Changed.OrderByDescending(t => t.NormalizedError).ToList();
                var layers = changed.Select(t => t.Layer).Distinct().ToList();
                var detail = new StringBuilder();
                detail.Append($"{changed.Count} of {compared.Count} compared tensors differ from {claimText} by more than quantization can explain");
                detail.Append(layers.Count > 0 ? $", in {layers.Count} layer group(s): {string.Join(", ", layers.Take(12))}{(layers.Count > 12 ? ", ..." : "")}. " : ". ");
                if (r.ShapeMismatch.Count > 0) detail.Append($"Shapes differ: {string.Join("; ", r.ShapeMismatch.Take(5))}. ");
                if (r.OnlyInCandidate.Count > 0) detail.Append($"Tensors not in the base: {string.Join(", ", r.OnlyInCandidate.Take(8))}. ");
                detail.Append("The file is not a plain quantization: it was fine-tuned, merged, abliterated or otherwise edited. That is not proof of a backdoor, " +
                    "but the claim 'quantization of the official model' is false, so treat it as an unaudited derivative.\nMost changed:");
                foreach (var t in changed.Take(10))
                    detail.Append(CultureInfo.InvariantCulture, $"\n  {t.Name} ({t.CandidateType}): normalized error {t.NormalizedError:0.00}{(double.IsNaN(t.RescaledError) ? "" : $" ({t.RescaledError:0.00} after rescaling)")}, relative L2 {t.RelativeError:P1}, cosine {t.Cosine:0.0000}");
                detail.Append($"\n{stats}\n{table}");
                report.Findings.Add(new Finding("L001", Severity.High, "Weights differ from the claimed base beyond quantization noise", detail.ToString(), "weights"));
                break;
            case LineageVerdict.Inconclusive:
                break;
        }

        var skipped = r.Tensors.Where(t => t.Skipped is not null).ToList();
        if (skipped.Count > 0 || r.OnlyInBase.Count > 0 || compared.Count == 0)
        {
            var reasons = skipped.GroupBy(t => t.Skipped!).Select(g => $"{g.Count()} tensor(s): {g.Key}");
            report.Findings.Add(new Finding("L004", compared.Count == 0 ? Severity.Low : Severity.Info,
                compared.Count == 0 ? "Weights could not be compared" : "Some tensors were not compared",
                string.Join("; ", reasons.Concat(r.OnlyInBase.Count > 0 ? [$"{r.OnlyInBase.Count} base tensor(s) missing from the candidate"] : [])) +
                (compared.Count == 0 ? ". No verdict." : ". The verdict covers the compared tensors only."), "weights"));
        }
        return report;
    }

    /// <summary>Per-layer summary: worst normalized error and cosine of each layer group.</summary>
    public static string Table(LineageResult r)
    {
        var groups = r.Compared.GroupBy(t => t.Layer)
            .OrderBy(g => g.Key == "other" ? -1 : int.Parse(g.Key[4..], CultureInfo.InvariantCulture)).ToList();
        if (groups.Count == 0) return "";
        var b = new StringBuilder("layer       tensors  max norm.err  min cosine  max rel.L2  changed");
        foreach (var g in groups)
            b.Append(CultureInfo.InvariantCulture,
                $"\n{g.Key,-10}  {g.Count(),7}  {g.Max(t => t.NormalizedError),12:0.00}  {g.Min(t => t.Cosine),10:0.0000}  {g.Max(t => t.RelativeError),10:P1}  {(g.Any(t => t.Modified) ? $"{g.Count(t => t.Modified)} CHANGED" : "")}{(g.Any(t => t.Rescaled) ? $" {g.Count(t => t.Rescaled)} rescaled" : "")}");
        return b.ToString();
    }

    static double Median(IEnumerable<double> values)
    {
        var v = values.OrderBy(x => x).ToList();
        return v.Count == 0 ? 0 : v.Count % 2 == 1 ? v[v.Count / 2] : (v[v.Count / 2 - 1] + v[v.Count / 2]) / 2;
    }
}
