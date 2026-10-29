using System.Text.Json;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Tests;

public sealed class DequantTests
{
    /// <summary>
    /// Fixtures: random blocks with sane fp16 scales, dequantized by llama.cpp's gguf-py (gguf.quants.dequantize).
    /// Q8_K is computed as d * q, since gguf-py has no Q8_K dequantizer.
    /// </summary>
    public static TheoryData<string> Types() => ["Q4_0", "Q4_1", "Q5_0", "Q5_1", "Q8_0", "Q4_K", "Q5_K", "Q6_K", "Q8_K", "F32", "F16", "BF16"];

    static (uint Type, byte[] Data, float[] Expected) Fixture(string name)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "dequant-reference.json")));
        var t = doc.RootElement.GetProperty("types").GetProperty(name);
        var values = Convert.FromBase64String(t.GetProperty("values").GetString()!);
        var expected = new float[values.Length / 4];
        Buffer.BlockCopy(values, 0, expected, 0, values.Length);
        return (t.GetProperty("type").GetUInt32(), Convert.FromBase64String(t.GetProperty("data").GetString()!), expected);
    }

    [Theory]
    [MemberData(nameof(Types))]
    public void Matches_llama_cpp_reference(string name)
    {
        var (type, data, expected) = Fixture(name);
        Assert.Equal(data.Length, GgmlDequant.ByteCount(type, expected.Length));
        var actual = new float[expected.Length];
        var steps = new float[expected.Length];
        GgmlDequant.Dequantize(type, data, actual, steps);
        for (var i = 0; i < expected.Length; i++)
            Assert.True(MathF.Abs(actual[i] - expected[i]) <= 1e-6f * MathF.Max(1, MathF.Abs(expected[i])), $"{name}[{i}]: {actual[i]} != {expected[i]}");
        Assert.All(steps, s => Assert.True(s >= 0 && float.IsFinite(s)));
    }

    [Fact]
    public void Q8_0_step_is_the_block_scale()
    {
        var block = new byte[34];
        BitConverter.TryWriteBytes(block, (Half)0.5f);
        block[2] = 3;
        block[3] = unchecked((byte)-2);
        var values = new float[32];
        var steps = new float[32];
        GgmlDequant.Dequantize(GgmlDequant.Q8_0, block, values, steps);
        Assert.Equal([1.5f, -1f], values[..2]);
        Assert.All(steps, s => Assert.Equal(0.5f, s));
    }

    [Fact]
    public void Unsupported_types_and_partial_blocks_are_rejected()
    {
        Assert.False(GgmlDequant.IsSupported(10)); // Q2_K
        Assert.Throws<NotSupportedException>(() => GgmlDequant.Dequantize(10, new byte[84], new float[256]));
        Assert.Throws<ArgumentException>(() => GgmlDequant.ByteCount(GgmlDequant.Q4_K, 100));
        Assert.Throws<ArgumentException>(() => GgmlDequant.Dequantize(GgmlDequant.Q8_0, new byte[10], new float[32]));
    }
}
