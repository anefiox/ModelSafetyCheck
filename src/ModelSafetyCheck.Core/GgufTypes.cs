namespace ModelSafetyCheck.Core;

public enum GgufValueType : uint
{
    UInt8 = 0,
    Int8 = 1,
    UInt16 = 2,
    Int16 = 3,
    UInt32 = 4,
    Int32 = 5,
    Float32 = 6,
    Bool = 7,
    String = 8,
    Array = 9,
    UInt64 = 10,
    Int64 = 11,
    Float64 = 12,
}

public readonly record struct GgmlTypeInfo(string Name, int BlockSize, int TypeSize);

/// <summary>Block layout of the GGML tensor types, used to compute how many bytes a tensor occupies.</summary>
public static class GgmlTypes
{
    static readonly Dictionary<uint, GgmlTypeInfo> Known = new()
    {
        [0] = new("F32", 1, 4),
        [1] = new("F16", 1, 2),
        [2] = new("Q4_0", 32, 18),
        [3] = new("Q4_1", 32, 20),
        [6] = new("Q5_0", 32, 22),
        [7] = new("Q5_1", 32, 24),
        [8] = new("Q8_0", 32, 34),
        [9] = new("Q8_1", 32, 36),
        [10] = new("Q2_K", 256, 84),
        [11] = new("Q3_K", 256, 110),
        [12] = new("Q4_K", 256, 144),
        [13] = new("Q5_K", 256, 176),
        [14] = new("Q6_K", 256, 210),
        [15] = new("Q8_K", 256, 292),
        [16] = new("IQ2_XXS", 256, 66),
        [17] = new("IQ2_XS", 256, 74),
        [18] = new("IQ3_XXS", 256, 98),
        [19] = new("IQ1_S", 256, 50),
        [20] = new("IQ4_NL", 32, 18),
        [21] = new("IQ3_S", 256, 110),
        [22] = new("IQ2_S", 256, 82),
        [23] = new("IQ4_XS", 256, 136),
        [24] = new("I8", 1, 1),
        [25] = new("I16", 1, 2),
        [26] = new("I32", 1, 4),
        [27] = new("I64", 1, 8),
        [28] = new("F64", 1, 8),
        [29] = new("IQ1_M", 256, 56),
        [30] = new("BF16", 1, 2),
        [34] = new("TQ1_0", 256, 54),
        [35] = new("TQ2_0", 256, 66),
        [39] = new("MXFP4", 32, 17),
    };

    public static bool TryGet(uint type, out GgmlTypeInfo info) => Known.TryGetValue(type, out info);

    public static string NameOf(uint type) => TryGet(type, out var info) ? info.Name : $"unknown({type})";
}
