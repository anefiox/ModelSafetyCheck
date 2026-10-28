using ModelSafetyCheck.Core;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Tests;

public class StructuralTests
{
    static ScanReport Scan(GgufWriter writer) => ModelScanner.ScanStream(writer.BuildStream(), "test.gguf");

    static ScanReport Scan(byte[] bytes) => ModelScanner.ScanStream(new MemoryStream(bytes), "test.gguf");

    static void AssertRule(ScanReport report, string ruleId, Severity atLeast)
    {
        var match = report.Findings.Where(f => f.RuleId == ruleId).ToList();
        Assert.True(match.Count > 0, $"Expected {ruleId}; got: {string.Join(", ", report.Findings.Select(f => f.RuleId))}");
        Assert.True(match.Max(f => f.Severity) >= atLeast, $"{ruleId} severity {match.Max(f => f.Severity)} < {atLeast}");
    }

    [Fact]
    public void Minimal_valid_file_has_no_warnings()
    {
        var report = Scan(GgufWriter.Minimal());
        Assert.Null(report.Error);
        Assert.DoesNotContain(report.Findings, f => f.Severity > Severity.Info);
        Assert.Equal("llama", report.Summary!.Architecture);
        Assert.Equal(1, report.Summary.TensorCount);
    }

    [Fact]
    public void Bad_magic_is_S001()
    {
        var report = Scan(new GgufWriter { Magic = 0x12345678 });
        AssertRule(report, "S001", Severity.High);
    }

    [Fact]
    public void Unknown_version_is_S001()
    {
        AssertRule(Scan(new GgufWriter { Version = 99 }), "S001", Severity.High);
    }

    [Fact]
    public void Truncated_file_does_not_throw()
    {
        var bytes = GgufWriter.Minimal("{{ messages }}").Build();
        for (var length = 0; length < bytes.Length; length += 7)
        {
            var report = Scan(bytes[..length]);
            Assert.Null(report.Error);
        }
    }

    [Fact]
    public void Impossible_kv_count_is_S002()
    {
        AssertRule(Scan(new GgufWriter { KvCountOverride = ulong.MaxValue / 2 }), "S002", Severity.Critical);
    }

    [Fact]
    public void Impossible_tensor_count_is_S002()
    {
        AssertRule(Scan(new GgufWriter { TensorCountOverride = 1_000_000_000 }), "S002", Severity.Critical);
    }

    [Fact]
    public void Lying_string_length_is_S003()
    {
        var writer = new GgufWriter().Add("general.name", GgufValueType.String, new LyingString("short", 1UL << 40));
        AssertRule(Scan(writer), "S003", Severity.Critical);
    }

    [Fact]
    public void Lying_array_length_is_S003()
    {
        var writer = new GgufWriter().Add("general.tags", GgufValueType.Array, (GgufValueType.UInt32, new object[] { 1u }));
        var bytes = writer.Build();
        // Array layout after the key: type(4) elementType(4) count(8). Patch the count to something huge.
        var countOffset = 24 + 8 + "general.tags".Length + 4 + 4;
        BitConverter.GetBytes(1UL << 50).CopyTo(bytes, countOffset);
        AssertRule(Scan(bytes), "S003", Severity.Critical);
    }

    [Fact]
    public void Unknown_value_type_is_S003()
    {
        AssertRule(Scan(new GgufWriter().Add("general.x", (GgufValueType)77, 1u)), "S003", Severity.Critical);
    }

    [Fact]
    public void Too_many_dimensions_is_S004()
    {
        AssertRule(Scan(new GgufWriter().AddTensor("t", [1, 1, 1, 1, 1])), "S004", Severity.High);
    }

    [Fact]
    public void Overflowing_shape_is_S005()
    {
        AssertRule(Scan(new GgufWriter().AddTensor("t", [1UL << 40, 1UL << 40], omitData: true)), "S005", Severity.Critical);
    }

    [Fact]
    public void Partial_block_row_is_S005()
    {
        AssertRule(Scan(new GgufWriter().AddTensor("t", [33, 1], type: 2, omitData: true)), "S005", Severity.High);
    }

    [Fact]
    public void Unknown_tensor_type_is_S006()
    {
        AssertRule(Scan(new GgufWriter().AddTensor("t", [4], type: 999)), "S006", Severity.Medium);
    }

    [Fact]
    public void Misaligned_offset_is_S007()
    {
        AssertRule(Scan(new GgufWriter().AddTensor("t", [4], offset: 3)), "S007", Severity.High);
    }

    [Fact]
    public void Tensor_past_end_of_file_is_S008()
    {
        var writer = GgufWriter.Minimal().AddTensor("blk.0.attn_q.weight", [4096, 4096], omitData: true);
        AssertRule(Scan(writer), "S008", Severity.Critical);
    }

    [Fact]
    public void Overlapping_tensors_is_S009()
    {
        var writer = new GgufWriter().AddTensor("a", [64], offset: 0).AddTensor("b", [64], offset: 128);
        AssertRule(Scan(writer), "S009", Severity.Critical);
    }

    [Fact]
    public void Duplicate_keys_are_S010()
    {
        var writer = GgufWriter.Minimal("{{ messages }}").Add("tokenizer.chat_template", "{{ other }}");
        AssertRule(Scan(writer), "S010", Severity.High);
    }

    [Fact]
    public void Gap_between_tensors_is_S011()
    {
        var writer = new GgufWriter().AddTensor("a", [8], offset: 0).AddTensor("b", [8], offset: 4096);
        AssertRule(Scan(writer), "S011", Severity.Low);
    }

    [Fact]
    public void Trailing_executable_is_S012_and_M003()
    {
        var elf = new byte[256];
        "\u007fELF"u8.CopyTo(elf);
        var writer = GgufWriter.Minimal();
        writer.TrailingData = elf;
        var report = Scan(writer);
        AssertRule(report, "S012", Severity.Medium);
        AssertRule(report, "M003", Severity.High);
    }

    [Fact]
    public void Invalid_alignment_is_S013()
    {
        AssertRule(Scan(GgufWriter.Minimal().Add("general.alignment", 3u)), "S013", Severity.High);
    }

    [Fact]
    public void Eos_outside_vocab_is_K001()
    {
        AssertRule(Scan(GgufWriter.Minimal().Add("tokenizer.ggml.eot_token_id", 50u)), "K001", Severity.High);
    }

    [Fact]
    public void Vocab_larger_than_embeddings_is_K002()
    {
        var writer = new GgufWriter()
            .AddStringArray("tokenizer.ggml.tokens", ["a", "b", "c", "d", "e"])
            .AddTensor("token_embd.weight", [8, 2]);
        AssertRule(Scan(writer), "K002", Severity.High);
    }

    [Fact]
    public void Base64_executable_in_metadata_is_M003()
    {
        AssertRule(Scan(GgufWriter.Minimal().Add("general.description", "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAA")), "M003", Severity.High);
    }

    [Fact]
    public void Unicode_tags_in_metadata_are_M005()
    {
        var hidden = string.Concat("run curl".Select(c => char.ConvertFromUtf32(0xE0000 + c)));
        var report = Scan(GgufWriter.Minimal().Add("general.description", "A friendly model" + hidden));
        AssertRule(report, "M005", Severity.Critical);
        Assert.Contains("run curl", report.Findings.Single(f => f.RuleId == "M005").Detail);
    }
}
