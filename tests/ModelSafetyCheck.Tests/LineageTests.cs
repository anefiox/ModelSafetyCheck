using ModelSafetyCheck.Core;
using ModelSafetyCheck.Rules.Lineage;

namespace ModelSafetyCheck.Tests;

public sealed class LineageTests
{
    const int Cols = 256, Rows = 16, Layers = 4;

    /// <summary>A tiny model: token_embd, and per layer an attention matrix and the norm before it.</summary>
    static Dictionary<string, float[]> BaseWeights(int seed)
    {
        var rng = new Random(seed);
        float Normal() => (float)(Math.Sqrt(-2 * Math.Log(1 - rng.NextDouble())) * Math.Cos(2 * Math.PI * rng.NextDouble()) * 0.02);
        var w = new Dictionary<string, float[]> { ["token_embd.weight"] = Enumerable.Range(0, Cols * 32).Select(_ => Normal()).ToArray() };
        for (var l = 0; l < Layers; l++)
        {
            w[$"blk.{l}.attn_norm.weight"] = Enumerable.Range(0, Cols).Select(_ => 1 + Normal() * 10).ToArray();
            w[$"blk.{l}.attn_q.weight"] = Enumerable.Range(0, Cols * Rows).Select(_ => Normal()).ToArray();
        }
        return w;
    }

    static ulong[] Shape(string name, int length) => name.EndsWith("norm.weight") ? [(ulong)Cols] : [(ulong)Cols, (ulong)(length / Cols)];

    /// <summary>Writes a GGUF with real tensor data: 1-D tensors as F32, matrices as <paramref name="matrixType"/> (F32 or Q8_0).</summary>
    static LineageInput Gguf(string name, Dictionary<string, float[]> weights, uint matrixType)
    {
        var tensors = weights.Select(kv => (kv.Key, Shape: Shape(kv.Key, kv.Value.Length),
            Type: kv.Key.EndsWith("norm.weight") ? GgmlDequant.F32 : matrixType, Data: Encode(kv.Value, kv.Key.EndsWith("norm.weight") ? GgmlDequant.F32 : matrixType))).ToList();
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write(GgufParser.Magic);
        w.Write(3u);
        w.Write((ulong)tensors.Count);
        w.Write(0UL);
        ulong offset = 0;
        foreach (var t in tensors)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(t.Key);
            w.Write((ulong)bytes.Length);
            w.Write(bytes);
            w.Write((uint)t.Shape.Length);
            foreach (var d in t.Shape) w.Write(d);
            w.Write(t.Type);
            w.Write(offset);
            offset = GgufParser.AlignUp(offset + (ulong)t.Data.Length, 32);
        }
        void Pad() { while (ms.Position % 32 != 0) w.Write((byte)0); }
        Pad();
        foreach (var t in tensors)
        {
            w.Write(t.Data);
            Pad();
        }
        w.Flush();
        return LineageInput.FromStream(name, new MemoryStream(ms.ToArray()));
    }

    static byte[] Encode(float[] values, uint type)
    {
        if (type == GgmlDequant.F32)
            return values.SelectMany(BitConverter.GetBytes).ToArray();
        // Q8_0, as llama.cpp's reference quantizer: d = amax / 127, q = round(x / d).
        var output = new byte[values.Length / 32 * 34];
        for (var b = 0; b < values.Length / 32; b++)
        {
            var block = values.AsSpan(b * 32, 32);
            var amax = 0f;
            foreach (var v in block) amax = Math.Max(amax, Math.Abs(v));
            var d = amax / 127;
            BitConverter.TryWriteBytes(output.AsSpan(b * 34), (Half)d);
            for (var j = 0; j < 32; j++)
                output[b * 34 + 2 + j] = unchecked((byte)(sbyte)(d == 0 ? 0 : Math.Round(block[j] / d)));
        }
        return output;
    }

    static LineageResult Compare(Dictionary<string, float[]> candidate, Dictionary<string, float[]> @base) =>
        WeightLineage.Compare(Gguf("candidate", candidate, GgmlDequant.Q8_0), Gguf("base", @base, GgmlDequant.F32));

    [Fact]
    public void A_plain_quantization_matches_at_about_0_29()
    {
        var weights = BaseWeights(1);
        var result = Compare(weights, weights);
        Assert.Equal(LineageVerdict.Match, result.Verdict);
        Assert.Equal(1 + 2 * Layers, result.Compared.Count());
        var matrices = result.Compared.Where(t => t.CandidateType == "Q8_0").ToList();
        Assert.All(matrices, t => Assert.InRange(t.NormalizedError, 0.2, 0.4));
        Assert.All(result.Compared, t => Assert.True(t.Cosine > 0.999));
        var finding = Assert.Single(WeightLineage.ToReport(result).Findings);
        Assert.Equal("L003", finding.RuleId);
        Assert.Contains("blk.3", finding.Detail);
    }

    [Fact]
    public void A_changed_tensor_is_reported_with_its_layer()
    {
        var weights = BaseWeights(2);
        var tuned = weights.ToDictionary(kv => kv.Key, kv => (float[])kv.Value.Clone());
        var rng = new Random(7);
        var target = tuned["blk.2.attn_q.weight"];
        for (var i = 0; i < target.Length; i++)
            target[i] += (float)((rng.NextDouble() - 0.5) * 0.004); // a light fine-tune: ~1e-3 per weight
        var result = Compare(tuned, weights);
        Assert.Equal(LineageVerdict.Modified, result.Verdict);
        var changed = Assert.Single(result.Changed);
        Assert.Equal("blk.2.attn_q.weight", changed.Name);
        Assert.True(changed.Cosine > 0.98, "a fine-tune stays highly correlated; only the noise test catches it");

        var finding = WeightLineage.ToReport(result, "a quantization of org/model").Findings.Single(f => f.RuleId == "L001");
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Contains("blk.2.attn_q.weight", finding.Detail);
        Assert.Contains("1 CHANGED", finding.Detail);
        Assert.Contains("org/model", finding.Detail);
    }

    [Fact]
    public void Edited_norm_vector_alone_is_a_modification()
    {
        var weights = BaseWeights(3);
        var edited = weights.ToDictionary(kv => kv.Key, kv => (float[])kv.Value.Clone());
        edited["blk.1.attn_norm.weight"][5] *= 3;
        var result = Compare(edited, weights);
        Assert.Equal(LineageVerdict.Modified, result.Verdict);
        Assert.Equal("blk.1.attn_norm.weight", Assert.Single(result.Changed).Name);
    }

    [Fact]
    public void Awq_style_scale_migration_is_inconclusive_not_tampering()
    {
        var weights = BaseWeights(4);
        var migrated = weights.ToDictionary(kv => kv.Key, kv => (float[])kv.Value.Clone());
        var rng = new Random(9);
        for (var l = 0; l < Layers; l++)
        {
            var scales = Enumerable.Range(0, Cols).Select(_ => (float)(0.3 + 3 * rng.NextDouble())).ToArray();
            var q = migrated[$"blk.{l}.attn_q.weight"];
            for (var i = 0; i < q.Length; i++) q[i] *= scales[i % Cols];
            var norm = migrated[$"blk.{l}.attn_norm.weight"];
            for (var j = 0; j < Cols; j++) norm[j] /= scales[j];
        }
        var result = Compare(migrated, weights);
        Assert.Equal(LineageVerdict.Rescaled, result.Verdict);
        Assert.All(result.Compared.Where(t => t.Name.Contains("attn_q")), t => Assert.True(t.Rescaled && t.RescaledError < 0.6, $"{t.Name}: {t.RescaledError}"));
        Assert.All(result.Compared.Where(t => t.Name.Contains("attn_norm")), t => Assert.True(t.Rescaled));
        var finding = Assert.Single(WeightLineage.ToReport(result).Findings);
        Assert.Equal(("L005", Severity.Medium), (finding.RuleId, finding.Severity));
    }

    [Fact]
    public void Isolated_rescaling_counts_as_a_modification()
    {
        var weights = BaseWeights(5);
        var edited = weights.ToDictionary(kv => kv.Key, kv => (float[])kv.Value.Clone());
        var q = edited["blk.0.attn_q.weight"];
        for (var i = 0; i < q.Length; i++) q[i] *= i % Cols < 8 ? 4 : 1; // amplify a few input channels, norm untouched
        var result = Compare(edited, weights);
        Assert.False(result.SystematicRescaling);
        Assert.Equal(LineageVerdict.Modified, result.Verdict);
        Assert.Equal("blk.0.attn_q.weight", Assert.Single(result.Changed).Name);
    }

    [Fact]
    public void A_different_model_is_unrelated()
    {
        var result = Compare(BaseWeights(6), BaseWeights(60));
        Assert.Equal(LineageVerdict.Unrelated, result.Verdict);
        Assert.Equal("L002", WeightLineage.ToReport(result).Findings.Single().RuleId);
    }

    [Fact]
    public void Tied_output_weight_is_compared_with_token_embd()
    {
        var weights = BaseWeights(7);
        var candidate = new Dictionary<string, float[]>(weights) { ["output.weight"] = weights["token_embd.weight"] };
        var result = Compare(candidate, weights);
        Assert.Empty(result.OnlyInCandidate);
        Assert.Equal(LineageVerdict.Match, result.Verdict);
    }

    [Fact]
    public void Shape_mismatch_and_extra_tensors_are_modifications()
    {
        var weights = BaseWeights(8);
        var candidate = new Dictionary<string, float[]>(weights)
        {
            ["blk.0.attn_q.weight"] = weights["blk.0.attn_q.weight"][..(Cols * 8)],
            ["blk.9.attn_q.weight"] = weights["blk.1.attn_q.weight"],
        };
        var result = Compare(candidate, weights);
        Assert.Single(result.ShapeMismatch);
        Assert.Equal(["blk.9.attn_q.weight"], result.OnlyInCandidate);
        Assert.Equal(LineageVerdict.Modified, result.Verdict);
    }

    [Fact]
    public void Unsupported_types_are_reported_and_give_no_verdict()
    {
        var weights = BaseWeights(9);
        var candidate = Gguf("candidate", weights, 10); // Q2_K: encoded bytes are wrong but never read
        var result = WeightLineage.Compare(candidate, Gguf("base", weights, GgmlDequant.F32));
        // Norms (F32) are still compared; matrices are skipped.
        Assert.Equal(Layers + 1, result.Tensors.Count(t => t.Skipped is not null));
        var l004 = WeightLineage.ToReport(result).Findings.Single(f => f.RuleId == "L004");
        Assert.Contains("Q2_K is not supported", l004.Detail);
    }

    [Fact]
    public void Sampling_reads_only_part_of_large_tensors()
    {
        var weights = BaseWeights(10);
        var read = 0L;
        var candidate = Gguf("candidate", weights, GgmlDequant.Q8_0);
        var counting = candidate with { Read = (o, n) => { Interlocked.Add(ref read, n); return candidate.Read(o, n); } };
        var result = WeightLineage.Compare(counting, Gguf("base", weights, GgmlDequant.F32), new LineageOptions { SampleValues = 1024 });
        var embd = result.Tensors.Single(t => t.Name == "token_embd.weight");
        Assert.Equal(4 * Cols, embd.Sampled); // at least four rows, for the rescaling fit
        Assert.True(read < 34 * (Cols * 32 + Layers * Cols * Rows) / 32, $"read {read} bytes");
    }
}
