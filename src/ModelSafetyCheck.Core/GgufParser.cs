using System.Buffers.Binary;
using System.Text;

namespace ModelSafetyCheck.Core;

public sealed record GgufLimits
{
    public ulong MaxKvCount { get; init; } = 1 << 16;
    public ulong MaxTensorCount { get; init; } = 1 << 20;
    public ulong MaxKeyLength { get; init; } = 1 << 16;

    /// <summary>Longer strings are skipped (and reported) instead of loaded.</summary>
    public ulong MaxStringLength { get; init; } = 16 << 20;

    public ulong MaxArrayLength { get; init; } = 1 << 24;
    public int MaxArrayDepth { get; init; } = 4;
    public uint MaxDimensions { get; init; } = 64;

    /// <summary>Large integer arrays are normally skipped; these keys are kept because rules need them.</summary>
    public IReadOnlySet<string> KeepIntegerArrays { get; init; } = new HashSet<string> { "tokenizer.ggml.token_type" };

    public static GgufLimits Default { get; } = new();
}

/// <summary>
/// Strict GGUF header parser. Every declared length, count and size is checked against the bytes
/// actually left in the file before it is used, and hostile input produces findings, not exceptions.
/// </summary>
public static class GgufParser
{
    public const uint Magic = 0x46554747; // "GGUF" read as little-endian uint32
    public const ulong DefaultAlignment = 32;
    const int SmallArrayKeep = 64;

    public static GgufFile Parse(string path, GgufLimits? limits = null)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20);
        return Parse(stream, limits);
    }

    /// <summary>Parses from the start of a seekable stream. The stream is left open.</summary>
    public static GgufFile Parse(Stream stream, GgufLimits? limits = null)
    {
        stream.Position = 0;
        var file = new GgufFile { FileLength = stream.Length };
        try
        {
            ParseCore(new BoundedReader(stream), file, limits ?? GgufLimits.Default);
        }
        catch (GgufFormatException ex)
        {
            file.ParseFindings.Add(new Finding(ex.RuleId, ex.Severity, ex.Title, ex.Message, $"offset 0x{ex.Offset:X}"));
        }
        catch (EndOfStreamException)
        {
            file.ParseFindings.Add(new Finding("S003", Severity.Critical, "Unexpected end of file",
                "The file ended in the middle of a header structure.", $"offset 0x{stream.Position:X}"));
        }
        return file;
    }

    public static ulong AlignUp(ulong value, ulong alignment) =>
        value % alignment == 0 ? value : value + (alignment - value % alignment);

    static void ParseCore(BoundedReader reader, GgufFile file, GgufLimits limits)
    {
        if (reader.Length < 8)
            throw new GgufFormatException("S001", Severity.High, "Not a GGUF file", "The file is too small to contain a GGUF header.", 0);

        var magic = reader.U32("magic");
        if (magic != Magic)
            throw new GgufFormatException("S001", Severity.High, "Not a GGUF file", $"Bad magic 0x{magic:X8}; expected 'GGUF'.", 0);

        var version = reader.U32("version");
        if (version is < 1 or > 3)
        {
            if (BinaryPrimitives.ReverseEndianness(version) is >= 1 and <= 3)
                throw new GgufFormatException("S001", Severity.Medium, "Big-endian GGUF",
                    "This is a big-endian GGUF file, which this scanner does not analyse. Most runners cannot load it either.", 4);
            throw new GgufFormatException("S001", Severity.High, "Unsupported GGUF version", $"Version {version} is not a known GGUF version (1-3).", 4);
        }
        file.Version = version;
        var v1 = version == 1;

        var tensorCount = v1 ? reader.U32("tensor count") : reader.U64("tensor count");
        var kvCount = v1 ? reader.U32("metadata count") : reader.U64("metadata count");
        file.DeclaredTensorCount = tensorCount;
        file.DeclaredKvCount = kvCount;

        // Smallest possible encodings: key length + 1-byte key + type + 1-byte value; name length + 1-byte name + n_dims + 1 dim + type + offset.
        const ulong minKvBytes = 4 + 1 + 4 + 1;
        const ulong minTensorBytes = 4 + 1 + 4 + 4 + 4 + 8;
        if (kvCount > limits.MaxKvCount || kvCount > (ulong)reader.Remaining / minKvBytes)
            throw new GgufFormatException("S002", Severity.Critical, "Impossible metadata count",
                $"The header declares {kvCount} metadata entries, which cannot fit in a {reader.Length}-byte file. Loaders that pre-allocate from this count can crash or overflow.", 16);
        if (tensorCount > limits.MaxTensorCount || tensorCount > (ulong)reader.Remaining / minTensorBytes)
            throw new GgufFormatException("S002", Severity.Critical, "Impossible tensor count",
                $"The header declares {tensorCount} tensors, which cannot fit in a {reader.Length}-byte file. Loaders that pre-allocate from this count can crash or overflow.", 8);

        for (ulong i = 0; i < kvCount; i++)
        {
            var offset = reader.Position;
            var key = ReadKey(reader, v1, limits, "metadata key");
            var type = (GgufValueType)reader.U32("value type");
            var value = ReadValue(reader, type, v1, limits, 0, key);
            file.Metadata.Add(new GgufKv(key, type, value, offset));
        }
        file.MetadataComplete = true;

        for (ulong i = 0; i < tensorCount; i++)
        {
            var offset = reader.Position;
            var name = ReadKey(reader, v1, limits, "tensor name");
            var nDims = reader.U32("tensor n_dims");
            if (nDims > limits.MaxDimensions)
                throw new GgufFormatException("S004", Severity.Critical, "Absurd tensor dimension count",
                    $"Tensor '{name}' declares {nDims} dimensions (GGML supports 4).", offset);
            var dims = new ulong[nDims];
            for (var d = 0; d < nDims; d++)
                dims[d] = v1 ? reader.U32("tensor dimension") : reader.U64("tensor dimension");
            var type = reader.U32("tensor type");
            var dataOffset = reader.U64("tensor offset");
            file.Tensors.Add(new GgufTensorInfo(name, dims, type, dataOffset, offset));
        }
        file.TensorInfoComplete = true;

        var alignmentKv = file.Find("general.alignment");
        if (alignmentKv is not null)
        {
            var alignment = file.GetInteger("general.alignment");
            if (alignment is null or <= 0 or > 1 << 30 || (alignment & (alignment - 1)) != 0)
                file.ParseFindings.Add(new Finding("S013", Severity.High, "Invalid alignment",
                    $"general.alignment is '{alignmentKv.Value}', which is not a positive power of two. Runners compute tensor addresses from it; the default of {DefaultAlignment} was assumed.",
                    "kv:general.alignment"));
            else
                file.Alignment = (ulong)alignment.Value;
        }
        file.DataStart = (long)AlignUp((ulong)reader.Position, file.Alignment);
    }

    static string ReadKey(BoundedReader reader, bool v1, GgufLimits limits, string what)
    {
        var offset = reader.Position;
        var length = v1 ? reader.U32(what) : reader.U64(what);
        reader.Require(length, what);
        if (length > limits.MaxKeyLength)
            throw new GgufFormatException("S003", Severity.High, "Oversized key", $"A {what} is {length} bytes long.", offset);
        return Encoding.UTF8.GetString(reader.Bytes(length, what));
    }

    static object ReadString(BoundedReader reader, bool v1, GgufLimits limits, string what)
    {
        var length = v1 ? reader.U32(what) : reader.U64(what);
        reader.Require(length, what);
        if (length > limits.MaxStringLength)
        {
            reader.Skip(length, what);
            return new SkippedString(length);
        }
        return Encoding.UTF8.GetString(reader.Bytes(length, what));
    }

    static object ReadValue(BoundedReader reader, GgufValueType type, bool v1, GgufLimits limits, int depth, string key) => type switch
    {
        GgufValueType.UInt8 => (long)reader.U8(key),
        GgufValueType.Int8 => (long)(sbyte)reader.U8(key),
        GgufValueType.UInt16 => (long)reader.U16(key),
        GgufValueType.Int16 => (long)(short)reader.U16(key),
        GgufValueType.UInt32 => (long)reader.U32(key),
        GgufValueType.Int32 => (long)(int)reader.U32(key),
        GgufValueType.Float32 => (double)BitConverter.Int32BitsToSingle((int)reader.U32(key)),
        GgufValueType.Bool => reader.U8(key) != 0,
        GgufValueType.String => ReadString(reader, v1, limits, $"value of '{key}'"),
        GgufValueType.Array => ReadArray(reader, v1, limits, depth, key),
        GgufValueType.UInt64 => reader.U64(key),
        GgufValueType.Int64 => (long)reader.U64(key),
        GgufValueType.Float64 => BitConverter.Int64BitsToDouble((long)reader.U64(key)),
        _ => throw new GgufFormatException("S003", Severity.Critical, "Unknown metadata value type",
            $"Key '{key}' uses value type {(uint)type}, which does not exist.", reader.Position - 4),
    };

    static GgufArray ReadArray(BoundedReader reader, bool v1, GgufLimits limits, int depth, string key)
    {
        var offset = reader.Position;
        if (depth >= limits.MaxArrayDepth)
            throw new GgufFormatException("S003", Severity.High, "Arrays nested too deeply", $"Key '{key}' nests arrays more than {limits.MaxArrayDepth} levels deep.", offset);

        var elementType = (GgufValueType)reader.U32($"array type of '{key}'");
        var count = v1 ? reader.U32($"array length of '{key}'") : reader.U64($"array length of '{key}'");
        var minSize = MinEncodedSize(elementType, v1)
            ?? throw new GgufFormatException("S003", Severity.Critical, "Unknown array element type",
                $"Key '{key}' declares array element type {(uint)elementType}, which does not exist.", offset);

        if (count > (ulong)reader.Remaining / minSize)
            throw new GgufFormatException("S003", Severity.Critical, "Array length exceeds file",
                $"Key '{key}' declares {count} elements, which cannot fit in the remaining {reader.Remaining} bytes. Loaders that trust this length can over-allocate or read out of bounds.", offset);
        if (count > limits.MaxArrayLength)
            throw new GgufFormatException("S003", Severity.High, "Array too long", $"Key '{key}' declares {count} elements.", offset);

        switch (elementType)
        {
            case GgufValueType.String:
            {
                var items = new List<string>((int)Math.Min(count, 1 << 16));
                for (ulong i = 0; i < count; i++)
                    items.Add(ReadString(reader, v1, limits, $"element of '{key}'") is string s ? s : "");
                return new GgufArray(elementType, count) { Strings = items };
            }
            case GgufValueType.Array:
            {
                var items = new List<GgufArray>();
                for (ulong i = 0; i < count; i++)
                    items.Add(ReadArray(reader, v1, limits, depth + 1, key));
                return new GgufArray(elementType, count) { Arrays = items };
            }
            default:
                if (count > SmallArrayKeep && limits.KeepIntegerArrays.Contains(key) && depth == 0 && IsInteger(elementType))
                {
                    var integers = new long[count];
                    for (ulong i = 0; i < count; i++)
                        integers[i] = Convert.ToInt64(ReadValue(reader, elementType, v1, limits, depth + 1, key));
                    return new GgufArray(elementType, count) { Integers = integers };
                }
                if (count > SmallArrayKeep)
                {
                    reader.Skip(count * minSize, $"array '{key}'");
                    return new GgufArray(elementType, count);
                }
                var values = new List<object>((int)count);
                for (ulong i = 0; i < count; i++)
                    values.Add(ReadValue(reader, elementType, v1, limits, depth + 1, key));
                return new GgufArray(elementType, count) { Values = values };
        }
    }

    static bool IsInteger(GgufValueType type) =>
        type is GgufValueType.UInt8 or GgufValueType.Int8 or GgufValueType.UInt16 or GgufValueType.Int16 or GgufValueType.UInt32 or GgufValueType.Int32 or GgufValueType.Int64;

    static ulong? MinEncodedSize(GgufValueType type, bool v1) => type switch
    {
        GgufValueType.UInt8 or GgufValueType.Int8 or GgufValueType.Bool => 1,
        GgufValueType.UInt16 or GgufValueType.Int16 => 2,
        GgufValueType.UInt32 or GgufValueType.Int32 or GgufValueType.Float32 => 4,
        GgufValueType.UInt64 or GgufValueType.Int64 or GgufValueType.Float64 => 8,
        GgufValueType.String => v1 ? 4UL : 8UL,
        GgufValueType.Array => v1 ? 8UL : 12UL,
        _ => null,
    };
}

sealed class GgufFormatException(string ruleId, Severity severity, string title, string message, long offset) : Exception(message)
{
    public string RuleId { get; } = ruleId;
    public Severity Severity { get; } = severity;
    public string Title { get; } = title;
    public long Offset { get; } = offset;
}

/// <summary>Reads little-endian values and refuses any read that would run past the end of the stream.</summary>
sealed class BoundedReader(Stream stream)
{
    readonly byte[] _buffer = new byte[8];

    public long Length { get; } = stream.Length;
    public long Position => stream.Position;
    public long Remaining => Length - stream.Position;

    public void Require(ulong count, string what)
    {
        if (count > (ulong)Remaining)
            throw new GgufFormatException("S003", Severity.Critical, "Declared length exceeds file",
                $"The {what} declares {count} bytes but only {Remaining} remain. A loader that trusts this length reads out of bounds.", Position);
    }

    public byte U8(string what) => Fill(1, what)[0];
    public ushort U16(string what) => BinaryPrimitives.ReadUInt16LittleEndian(Fill(2, what));
    public uint U32(string what) => BinaryPrimitives.ReadUInt32LittleEndian(Fill(4, what));
    public ulong U64(string what) => BinaryPrimitives.ReadUInt64LittleEndian(Fill(8, what));

    public byte[] Bytes(ulong count, string what)
    {
        Require(count, what);
        var bytes = new byte[count];
        stream.ReadExactly(bytes);
        return bytes;
    }

    public void Skip(ulong count, string what)
    {
        Require(count, what);
        stream.Seek((long)count, SeekOrigin.Current);
    }

    ReadOnlySpan<byte> Fill(int count, string what)
    {
        Require((ulong)count, what);
        stream.ReadExactly(_buffer, 0, count);
        return _buffer.AsSpan(0, count);
    }
}
