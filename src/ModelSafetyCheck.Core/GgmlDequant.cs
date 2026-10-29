using System.Buffers.Binary;

namespace ModelSafetyCheck.Core;

/// <summary>
/// Converts GGML tensor data back to floats, following llama.cpp's reference dequantizers (ggml-quants.c).
/// Optionally also returns each value's quantization step: the distance between neighbouring representable
/// values at that position, so a caller can tell whether an original value could have produced it.
/// </summary>
public static class GgmlDequant
{
    public const uint F32 = 0, F16 = 1, Q4_0 = 2, Q4_1 = 3, Q5_0 = 6, Q5_1 = 7, Q8_0 = 8, Q4_K = 12, Q5_K = 13, Q6_K = 14, Q8_K = 15, BF16 = 30;

    static readonly HashSet<uint> Supported = [F32, F16, BF16, Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, Q4_K, Q5_K, Q6_K, Q8_K];

    public static bool IsSupported(uint type) => Supported.Contains(type);

    /// <summary>Bytes needed for <paramref name="elements"/> values (a whole number of blocks).</summary>
    public static long ByteCount(uint type, long elements)
    {
        if (!GgmlTypes.TryGet(type, out var info))
            throw new NotSupportedException($"Unknown GGML type {type}.");
        if (elements % info.BlockSize != 0)
            throw new ArgumentException($"{elements} values is not a whole number of {info.Name} blocks ({info.BlockSize}).");
        return elements / info.BlockSize * info.TypeSize;
    }

    /// <summary>
    /// Dequantizes <paramref name="values"/>.Length values from <paramref name="data"/>. When <paramref name="steps"/> is not
    /// empty it receives the quantization step of each value (0 for exact float formats' rounding is approximated by the ULP).
    /// </summary>
    public static void Dequantize(uint type, ReadOnlySpan<byte> data, Span<float> values, Span<float> steps = default)
    {
        var n = values.Length;
        if (data.Length < ByteCount(type, n))
            throw new ArgumentException("Not enough data for the requested number of values.");
        var withSteps = !steps.IsEmpty;
        if (withSteps && steps.Length < n)
            throw new ArgumentException("steps is shorter than values.");

        switch (type)
        {
            case F32:
                for (var i = 0; i < n; i++)
                {
                    values[i] = BinaryPrimitives.ReadSingleLittleEndian(data[(4 * i)..]);
                    if (withSteps) steps[i] = Ulp(values[i], 23);
                }
                return;
            case F16:
                for (var i = 0; i < n; i++)
                {
                    values[i] = Half16(data[(2 * i)..]);
                    if (withSteps) steps[i] = Ulp(values[i], 10);
                }
                return;
            case BF16:
                for (var i = 0; i < n; i++)
                {
                    values[i] = BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadUInt16LittleEndian(data[(2 * i)..]) << 16);
                    if (withSteps) steps[i] = Ulp(values[i], 7);
                }
                return;
        }

        GgmlTypes.TryGet(type, out var info);
        var blocks = n / info.BlockSize;
        for (var b = 0; b < blocks; b++)
        {
            var block = data.Slice(b * info.TypeSize, info.TypeSize);
            var y = values.Slice(b * info.BlockSize, info.BlockSize);
            var s = withSteps ? steps.Slice(b * info.BlockSize, info.BlockSize) : default;
            switch (type)
            {
                case Q8_0: BlockQ8_0(block, y, s); break;
                case Q4_0: BlockQ4_0(block, y, s); break;
                case Q4_1: BlockQ4_1(block, y, s); break;
                case Q5_0: BlockQ5_0(block, y, s); break;
                case Q5_1: BlockQ5_1(block, y, s); break;
                case Q4_K: BlockQ4_K(block, y, s); break;
                case Q5_K: BlockQ5_K(block, y, s); break;
                case Q6_K: BlockQ6_K(block, y, s); break;
                case Q8_K: BlockQ8_K(block, y, s); break;
                default: throw new NotSupportedException($"Dequantizing {GgmlTypes.NameOf(type)} is not supported.");
            }
        }
    }

    static float Half16(ReadOnlySpan<byte> b) => (float)BinaryPrimitives.ReadHalfLittleEndian(b);

    /// <summary>Spacing of floats with <paramref name="mantissaBits"/> near <paramref name="v"/>.</summary>
    static float Ulp(float v, int mantissaBits)
    {
        var a = MathF.Abs(v);
        if (a == 0 || !float.IsFinite(a)) return 0;
        return MathF.Pow(2, MathF.Floor(MathF.Log2(a)) - mantissaBits);
    }

    static void Fill(Span<float> steps, float step)
    {
        if (!steps.IsEmpty) steps.Fill(MathF.Abs(step));
    }

    // block_q8_0 { half d; int8 qs[32]; }
    static void BlockQ8_0(ReadOnlySpan<byte> b, Span<float> y, Span<float> s)
    {
        var d = Half16(b);
        for (var j = 0; j < 32; j++)
            y[j] = (sbyte)b[2 + j] * d;
        Fill(s, d);
    }

    // block_q4_0 { half d; uint8 qs[16]; }
    static void BlockQ4_0(ReadOnlySpan<byte> b, Span<float> y, Span<float> s)
    {
        var d = Half16(b);
        var qs = b[2..];
        for (var j = 0; j < 16; j++)
        {
            y[j] = ((qs[j] & 0x0F) - 8) * d;
            y[j + 16] = ((qs[j] >> 4) - 8) * d;
        }
        Fill(s, d);
    }

    // block_q4_1 { half d; half m; uint8 qs[16]; }
    static void BlockQ4_1(ReadOnlySpan<byte> b, Span<float> y, Span<float> s)
    {
        var d = Half16(b);
        var m = Half16(b[2..]);
        var qs = b[4..];
        for (var j = 0; j < 16; j++)
        {
            y[j] = (qs[j] & 0x0F) * d + m;
            y[j + 16] = (qs[j] >> 4) * d + m;
        }
        Fill(s, d);
    }

    // block_q5_0 { half d; uint8 qh[4]; uint8 qs[16]; }
    static void BlockQ5_0(ReadOnlySpan<byte> b, Span<float> y, Span<float> s)
    {
        var d = Half16(b);
        var qh = BinaryPrimitives.ReadUInt32LittleEndian(b[2..]);
        var qs = b[6..];
        for (var j = 0; j < 16; j++)
        {
            var xh0 = (int)((qh >> j) << 4) & 0x10;
            var xh1 = (int)(qh >> (j + 12)) & 0x10;
            y[j] = (((qs[j] & 0x0F) | xh0) - 16) * d;
            y[j + 16] = (((qs[j] >> 4) | xh1) - 16) * d;
        }
        Fill(s, d);
    }

    // block_q5_1 { half d; half m; uint8 qh[4]; uint8 qs[16]; }
    static void BlockQ5_1(ReadOnlySpan<byte> b, Span<float> y, Span<float> s)
    {
        var d = Half16(b);
        var m = Half16(b[2..]);
        var qh = BinaryPrimitives.ReadUInt32LittleEndian(b[4..]);
        var qs = b[8..];
        for (var j = 0; j < 16; j++)
        {
            var xh0 = (int)((qh >> j) << 4) & 0x10;
            var xh1 = (int)(qh >> (j + 12)) & 0x10;
            y[j] = ((qs[j] & 0x0F) | xh0) * d + m;
            y[j + 16] = ((qs[j] >> 4) | xh1) * d + m;
        }
        Fill(s, d);
    }

    // block_q8_K { float d; int8 qs[256]; int16 bsums[16]; }
    static void BlockQ8_K(ReadOnlySpan<byte> b, Span<float> y, Span<float> s)
    {
        var d = BinaryPrimitives.ReadSingleLittleEndian(b);
        for (var j = 0; j < 256; j++)
            y[j] = (sbyte)b[4 + j] * d;
        Fill(s, d);
    }

    /// <summary>The 6-bit scale and min of sub-block <paramref name="j"/> in a Q4_K/Q5_K block (get_scale_min_k4).</summary>
    static (int Scale, int Min) ScaleMinK4(int j, ReadOnlySpan<byte> q) => j < 4
        ? (q[j] & 63, q[j + 4] & 63)
        : ((q[j + 4] & 0x0F) | ((q[j - 4] >> 6) << 4), (q[j + 4] >> 4) | ((q[j] >> 6) << 4));

    // block_q4_K { half d; half dmin; uint8 scales[12]; uint8 qs[128]; }
    static void BlockQ4_K(ReadOnlySpan<byte> b, Span<float> y, Span<float> s)
    {
        var d = Half16(b);
        var min = Half16(b[2..]);
        var scales = b.Slice(4, 12);
        var q = b[16..];
        var withSteps = !s.IsEmpty;
        for (int j = 0, sub = 0, o = 0; j < 256; j += 64, sub += 2, o += 32)
        {
            var (sc1, m1) = ScaleMinK4(sub, scales);
            var (sc2, m2) = ScaleMinK4(sub + 1, scales);
            float d1 = d * sc1, dm1 = min * m1, d2 = d * sc2, dm2 = min * m2;
            for (var l = 0; l < 32; l++)
            {
                y[j + l] = d1 * (q[o + l] & 0x0F) - dm1;
                y[j + 32 + l] = d2 * (q[o + l] >> 4) - dm2;
            }
            if (withSteps)
            {
                s.Slice(j, 32).Fill(MathF.Abs(d1));
                s.Slice(j + 32, 32).Fill(MathF.Abs(d2));
            }
        }
    }

    // block_q5_K { half d; half dmin; uint8 scales[12]; uint8 qh[32]; uint8 qs[128]; }
    static void BlockQ5_K(ReadOnlySpan<byte> b, Span<float> y, Span<float> s)
    {
        var d = Half16(b);
        var min = Half16(b[2..]);
        var scales = b.Slice(4, 12);
        var qh = b.Slice(16, 32);
        var ql = b[48..];
        var withSteps = !s.IsEmpty;
        int u1 = 1, u2 = 2;
        for (int j = 0, sub = 0, o = 0; j < 256; j += 64, sub += 2, o += 32, u1 <<= 2, u2 <<= 2)
        {
            var (sc1, m1) = ScaleMinK4(sub, scales);
            var (sc2, m2) = ScaleMinK4(sub + 1, scales);
            float d1 = d * sc1, dm1 = min * m1, d2 = d * sc2, dm2 = min * m2;
            for (var l = 0; l < 32; l++)
            {
                y[j + l] = d1 * ((ql[o + l] & 0x0F) + ((qh[l] & u1) != 0 ? 16 : 0)) - dm1;
                y[j + 32 + l] = d2 * ((ql[o + l] >> 4) + ((qh[l] & u2) != 0 ? 16 : 0)) - dm2;
            }
            if (withSteps)
            {
                s.Slice(j, 32).Fill(MathF.Abs(d1));
                s.Slice(j + 32, 32).Fill(MathF.Abs(d2));
            }
        }
    }

    // block_q6_K { uint8 ql[128]; uint8 qh[64]; int8 scales[16]; half d; }
    static void BlockQ6_K(ReadOnlySpan<byte> b, Span<float> y, Span<float> s)
    {
        var d = Half16(b[208..]);
        var withSteps = !s.IsEmpty;
        for (var n = 0; n < 2; n++)
        {
            var ql = b.Slice(64 * n, 64);
            var qh = b.Slice(128 + 32 * n, 32);
            var sc = b.Slice(192 + 8 * n, 8);
            var yo = 128 * n;
            for (var l = 0; l < 32; l++)
            {
                var i = l / 16;
                var q1 = ((ql[l] & 0x0F) | (((qh[l] >> 0) & 3) << 4)) - 32;
                var q2 = ((ql[l + 32] & 0x0F) | (((qh[l] >> 2) & 3) << 4)) - 32;
                var q3 = ((ql[l] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
                var q4 = ((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
                float s1 = d * (sbyte)sc[i], s2 = d * (sbyte)sc[i + 2], s3 = d * (sbyte)sc[i + 4], s4 = d * (sbyte)sc[i + 6];
                y[yo + l] = s1 * q1;
                y[yo + l + 32] = s2 * q2;
                y[yo + l + 64] = s3 * q3;
                y[yo + l + 96] = s4 * q4;
                if (withSteps)
                {
                    s[yo + l] = MathF.Abs(s1);
                    s[yo + l + 32] = MathF.Abs(s2);
                    s[yo + l + 64] = MathF.Abs(s3);
                    s[yo + l + 96] = MathF.Abs(s4);
                }
            }
        }
    }
}
