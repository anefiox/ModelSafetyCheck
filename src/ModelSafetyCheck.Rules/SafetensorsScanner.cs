using System.Buffers.Binary;
using System.Text.Json;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Rules;

/// <summary>
/// Rules F001–F006 for .safetensors files: an 8-byte header length, a JSON header, then raw tensor data.
/// The format cannot execute code, but loaders still trust the header's offsets and the metadata strings.
/// </summary>
public static class SafetensorsScanner
{
    const long MaxHeaderBytes = 100L << 20;

    static readonly Dictionary<string, double> DtypeSizes = new()
    {
        ["F64"] = 8, ["F32"] = 4, ["F16"] = 2, ["BF16"] = 2, ["I64"] = 8, ["I32"] = 4, ["I16"] = 2, ["I8"] = 1, ["U8"] = 1, ["BOOL"] = 1,
        ["U16"] = 2, ["U32"] = 4, ["U64"] = 8, ["F8_E4M3"] = 1, ["F8_E5M2"] = 1, ["F8_E8M0"] = 1, ["F4"] = 0.5, ["F6_E2M3"] = 0.75, ["F6_E3M2"] = 0.75,
    };

    public static void Scan(Stream stream, ScanReport report)
    {
        var length = stream.Length;
        if (length < 8)
        {
            report.Findings.Add(new Finding("F001", Severity.High, "Not a safetensors file", "The file is shorter than the 8-byte header length.", "offset 0x0"));
            return;
        }

        Span<byte> prefix = stackalloc byte[8];
        stream.Position = 0;
        stream.ReadExactly(prefix);
        var headerLength = BinaryPrimitives.ReadUInt64LittleEndian(prefix);
        if (headerLength > MaxHeaderBytes || headerLength > (ulong)(length - 8))
        {
            report.Findings.Add(new Finding("F001", Severity.Critical, "Header length is impossible",
                $"The header claims {headerLength:N0} bytes but the file is {length:N0}. Loaders that trust it read out of bounds or allocate huge buffers.", "offset 0x0"));
            return;
        }

        var header = new byte[headerLength];
        stream.ReadExactly(header);
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(header, new JsonDocumentOptions { MaxDepth = 16 });
        }
        catch (JsonException ex)
        {
            report.Findings.Add(new Finding("F002", Severity.High, "Header is not valid JSON", ex.Message, "header"));
            return;
        }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                report.Findings.Add(new Finding("F002", Severity.High, "Header is not a JSON object", "", "header"));
                return;
            }

            var dataStart = 8 + (long)headerLength;
            var dataLength = length - dataStart;
            var tensors = new List<(string Name, long Begin, long End)>();
            var allKnown = true;

            foreach (var entry in doc.RootElement.EnumerateObject())
            {
                if (entry.Name == "__metadata__")
                {
                    CheckMetadata(entry.Value, report);
                    continue;
                }
                var location = $"tensor:{entry.Name}";
                if (entry.Value.ValueKind != JsonValueKind.Object ||
                    !entry.Value.TryGetProperty("dtype", out var dtypeEl) || !entry.Value.TryGetProperty("shape", out var shapeEl) || !entry.Value.TryGetProperty("data_offsets", out var offsetsEl) ||
                    dtypeEl.ValueKind != JsonValueKind.String ||
                    offsetsEl.ValueKind != JsonValueKind.Array || offsetsEl.GetArrayLength() != 2 || shapeEl.ValueKind != JsonValueKind.Array)
                {
                    report.Findings.Add(new Finding("F002", Severity.High, "Malformed tensor entry", "Expected dtype, shape and a two-element data_offsets.", location));
                    allKnown = false;
                    continue;
                }

                if (offsetsEl[0].ValueKind != JsonValueKind.Number || offsetsEl[1].ValueKind != JsonValueKind.Number ||
                    !offsetsEl[0].TryGetInt64(out var begin) || !offsetsEl[1].TryGetInt64(out var end) || begin < 0 || end < begin || end > dataLength)
                {
                    report.Findings.Add(new Finding("F004", Severity.Critical, "Tensor data lies outside the file",
                        $"data_offsets {offsetsEl.GetRawText()} do not fit in the {dataLength:N0}-byte data section. A loader that trusts them reads out of bounds.", location));
                    allKnown = false;
                    continue;
                }

                var dtype = dtypeEl.GetString() ?? "";
                if (!DtypeSizes.TryGetValue(dtype, out var size))
                {
                    report.Findings.Add(new Finding("F003", Severity.Medium, "Unknown tensor dtype", $"'{dtype}' is not a known safetensors dtype.", location));
                    allKnown = false;
                }
                else
                {
                    double elements = 1;
                    foreach (var d in shapeEl.EnumerateArray())
                        elements *= d.ValueKind == JsonValueKind.Number && d.TryGetInt64(out var n) && n >= 0 ? n : double.NaN;
                    var expected = elements * size;
                    if (double.IsNaN(expected) || Math.Abs(expected - (end - begin)) > 1)
                        report.Findings.Add(new Finding("F004", Severity.High, "Tensor size does not match its shape",
                            $"Shape {shapeEl.GetRawText()} of {dtype} needs {expected:N0} bytes but data_offsets cover {end - begin:N0}.", location));
                }
                tensors.Add((entry.Name, begin, end));
            }

            if (!allKnown)
                return;

            // Overlaps and unused space, like the GGUF layout checks.
            long cursor = 0;
            (string Name, long Begin, long End)? previous = null;
            foreach (var t in tensors.Where(t => t.End > t.Begin).OrderBy(t => t.Begin))
            {
                if (previous is { } p && t.Begin < p.End)
                    report.Findings.Add(new Finding("F005", Severity.Critical, "Overlapping tensors", $"'{t.Name}' overlaps '{p.Name}'.", $"tensor:{t.Name}"));
                else if (t.Begin > cursor)
                    CheckSlack(stream, dataStart + cursor, t.Begin - cursor, $"Unused gap before '{t.Name}'", report);
                cursor = Math.Max(cursor, t.End);
                previous = t;
            }
            if (dataLength > cursor)
                CheckSlack(stream, dataStart + cursor, dataLength - cursor, "Data after the last tensor", report);
        }
    }

    static void CheckMetadata(JsonElement metadata, ScanReport report)
    {
        if (metadata.ValueKind != JsonValueKind.Object)
        {
            report.Findings.Add(new Finding("F002", Severity.Medium, "__metadata__ is not an object", "", "__metadata__"));
            return;
        }
        foreach (var kv in metadata.EnumerateObject())
        {
            if (kv.Value.ValueKind == JsonValueKind.String)
                MetadataRules.CheckString(kv.Name, kv.Value.GetString()!, $"__metadata__:{kv.Name}", report.Findings);
            else
                report.Findings.Add(new Finding("F002", Severity.Low, "Non-string metadata value", "safetensors metadata values must be strings.", $"__metadata__:{kv.Name}"));
        }
    }

    static void CheckSlack(Stream stream, long start, long length, string title, ScanReport report)
    {
        var buffer = new byte[(int)Math.Min(length, 4 << 20)];
        stream.Position = start;
        stream.ReadExactly(buffer);
        var signature = TextHeuristics.FindBinarySignature(buffer);
        if (signature is not null)
            report.Findings.Add(new Finding("M003", Severity.High, "Executable or archive hidden in unused space", $"Found a {signature} in {length:N0} unused bytes.", $"offset 0x{start:X}"));
        var zeros = Array.TrueForAll(buffer, b => b == 0);
        report.Findings.Add(new Finding("F006", zeros ? Severity.Low : Severity.Medium, title,
            $"{length:N0} bytes are not used by any tensor{(zeros ? " (all zero)" : " and contain non-zero data")}.", $"offset 0x{start:X}"));
    }
}
