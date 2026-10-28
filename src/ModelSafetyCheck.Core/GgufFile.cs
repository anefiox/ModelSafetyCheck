namespace ModelSafetyCheck.Core;

/// <summary>An array value. String arrays keep their items; primitive arrays keep only small ones.</summary>
public sealed class GgufArray(GgufValueType elementType, ulong count)
{
    public GgufValueType ElementType { get; } = elementType;
    public ulong Count { get; } = count;
    public IReadOnlyList<string>? Strings { get; init; }
    public IReadOnlyList<object>? Values { get; init; }

    /// <summary>Large integer arrays that a rule needs (see <see cref="GgufLimits.KeepIntegerArrays"/>).</summary>
    public IReadOnlyList<long>? Integers { get; init; }
    public IReadOnlyList<GgufArray>? Arrays { get; init; }
}

/// <summary>A string value that was too large to load. The parser skipped it but it is still reported.</summary>
public sealed record SkippedString(ulong Length);

/// <summary>Integers are stored as <see cref="long"/> (or <see cref="ulong"/> for UInt64), floats as <see cref="double"/>.</summary>
public sealed record GgufKv(string Key, GgufValueType Type, object? Value, long Offset);

public sealed record GgufTensorInfo(string Name, ulong[] Dimensions, uint Type, ulong Offset, long InfoOffset);

public sealed class GgufFile
{
    public long FileLength { get; init; }
    public uint Version { get; internal set; }
    public ulong DeclaredTensorCount { get; internal set; }
    public ulong DeclaredKvCount { get; internal set; }
    public List<GgufKv> Metadata { get; } = [];
    public List<GgufTensorInfo> Tensors { get; } = [];

    /// <summary>Problems hit while parsing. Parsing stops at the first fatal one.</summary>
    public List<Finding> ParseFindings { get; } = [];

    public bool MetadataComplete { get; internal set; }
    public bool TensorInfoComplete { get; internal set; }
    public ulong Alignment { get; internal set; } = GgufParser.DefaultAlignment;
    public long DataStart { get; internal set; }

    public GgufKv? Find(string key) => Metadata.FirstOrDefault(k => k.Key == key);

    public string? GetString(string key) => Find(key)?.Value as string;

    public long? GetInteger(string key) => Find(key)?.Value switch
    {
        long l => l,
        ulong u when u <= long.MaxValue => (long)u,
        _ => null,
    };

    public GgufArray? GetArray(string key) => Find(key)?.Value as GgufArray;
}
