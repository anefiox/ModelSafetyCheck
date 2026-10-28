using System.Text;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Rules;

/// <summary>
/// Rules OX001–OX005 for .onnx models. Walks the protobuf (ModelProto → GraphProto → TensorProto, including
/// subgraphs) without loading weight data, and checks external-data locations (path traversal:
/// CVE-2022-25882, CVE-2024-27318, symlink bypasses CVE-2026-27489 / CVE-2026-34447), custom operator
/// domains (which need native libraries) and metadata.
/// </summary>
public static class OnnxScanner
{
    const int MaxDepth = 32;
    const long MaxStringBytes = 1 << 20;

    static readonly HashSet<string> StandardDomains = ["", "ai.onnx", "ai.onnx.ml", "ai.onnx.training", "ai.onnx.preview.training", "com.microsoft", "com.microsoft.nchwc", "com.microsoft.experimental", "org.pytorch.aten", "com.ms.internal.nhwc"];

    sealed class State
    {
        public readonly List<(string Tensor, string Location)> ExternalData = [];
        public readonly HashSet<string> Domains = [];
        public readonly List<(string Key, string Value)> Metadata = [];
        public int Tensors;
    }

    public static void Scan(Stream stream, ScanReport report, string? modelPath = null)
    {
        var state = new State();
        try
        {
            var r = new ProtoReader(stream);
            r.Message(0, stream.Length, 0, (field, wire, start, end) =>
            {
                switch (field)
                {
                    case 7 when wire == 2: Graph(r, start, end, 1, state); break;                 // ModelProto.graph
                    case 14 when wire == 2: state.Metadata.Add(KeyValue(r, start, end)); break;    // metadata_props
                    case 8 when wire == 2:                                                       // opset_import.domain
                        r.Message(start, end, 1, (f, w, s, e) => { if (f == 1 && w == 2) state.Domains.Add(r.String(s, e)); });
                        break;
                }
            });
        }
        catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException or OverflowException)
        {
            report.Findings.Add(new Finding("OX005", Severity.Medium, "ONNX file could not be fully parsed", ex.Message, null));
        }

        CheckExternalData(state, report, modelPath);

        var custom = state.Domains.Where(d => !StandardDomains.Contains(d)).ToList();
        if (custom.Count > 0)
            report.Findings.Add(new Finding("OX003", Severity.Medium, "Custom operator domains",
                $"The model uses operators from {string.Join(", ", custom.Take(10))}. Running it requires a custom-op library, which is native code from whoever built the model.", "opset_import"));

        foreach (var (key, value) in state.Metadata)
            MetadataRules.CheckString(key, value, $"metadata_props:{key}", report.Findings);

        report.Findings.Add(new Finding("OX004", Severity.Info, "ONNX model",
            $"{state.Tensors:N0} tensor(s), {state.ExternalData.Count:N0} stored in external files, operator domains: {string.Join(", ", state.Domains.Append("").Select(d => d.Length == 0 ? "ai.onnx" : d).Distinct())}.", null));
    }

    static void Graph(ProtoReader r, long start, long end, int depth, State state)
    {
        if (depth > MaxDepth) throw new InvalidDataException("Graphs nested too deeply");
        r.Message(start, end, depth, (field, wire, s, e) =>
        {
            if (wire != 2) return;
            switch (field)
            {
                case 5: Tensor(r, s, e, depth + 1, state); break;                                  // initializer
                case 15:                                                                          // sparse_initializer
                    r.Message(s, e, depth + 1, (f, w, ss, ee) => { if (w == 2 && f is 1 or 2) Tensor(r, ss, ee, depth + 2, state); });
                    break;
                case 1: Node(r, s, e, depth + 1, state); break;                                    // node
            }
        });
    }

    static void Node(ProtoReader r, long start, long end, int depth, State state)
    {
        r.Message(start, end, depth, (field, wire, s, e) =>
        {
            if (wire != 2) return;
            if (field == 7) state.Domains.Add(r.String(s, e));                                     // NodeProto.domain
            else if (field == 5)                                                                  // attribute
                r.Message(s, e, depth + 1, (f, w, ss, ee) =>
                {
                    if (w != 2) return;
                    if (f is 5 or 10) Tensor(r, ss, ee, depth + 2, state);                       // t, tensors
                    else if (f is 6 or 11) Graph(r, ss, ee, depth + 2, state);                   // g, graphs (subgraphs)
                });
        });
    }

    static void Tensor(ProtoReader r, long start, long end, int depth, State state)
    {
        state.Tensors++;
        var name = "";
        string? location = null;
        r.Message(start, end, depth, (field, wire, s, e) =>
        {
            if (wire != 2) return;
            if (field == 8) name = r.String(s, e);                                                 // TensorProto.name
            else if (field == 13)                                                                 // external_data
            {
                var (key, value) = KeyValue(r, s, e);
                if (key == "location") location = value;
            }
        });
        if (location is not null) state.ExternalData.Add((name, location));
    }

    static (string Key, string Value) KeyValue(ProtoReader r, long start, long end)
    {
        string key = "", value = "";
        r.Message(start, end, 99, (f, w, s, e) =>
        {
            if (w != 2) return;
            if (f == 1) key = r.String(s, e);
            else if (f == 2) value = r.String(s, e);
        });
        return (key, value);
    }

    static void CheckExternalData(State state, ScanReport report, string? modelPath)
    {
        var modelDir = modelPath is null ? null : Path.GetDirectoryName(Path.GetFullPath(modelPath));
        foreach (var group in state.ExternalData.GroupBy(x => x.Location))
        {
            var location = group.Key;
            var tensors = string.Join(", ", group.Take(3).Select(x => x.Tensor)) + (group.Count() > 3 ? $" (+{group.Count() - 3} more)" : "");
            var normalized = location.Replace('\\', '/');
            var sensitive = System.Text.RegularExpressions.Regex.IsMatch(normalized, @"(^|/)(etc/(passwd|shadow)|\.ssh/|\.aws/|\.env\b|windows/system32|\.git/)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            if (Path.IsPathRooted(location) || normalized.StartsWith('/') || normalized.Split('/').Contains("..") || System.Text.RegularExpressions.Regex.IsMatch(location, @"^[A-Za-z]:"))
            {
                report.Findings.Add(new Finding("OX001", sensitive ? Severity.Critical : Severity.High, "External data path leaves the model folder",
                    $"Tensor(s) {tensors} load data from '{location}'. Old onnx/onnxruntime versions read it (path traversal, CVE-2022-25882, CVE-2024-27318): a model can make the loader read arbitrary files.",
                    $"external_data:{location}"));
                continue;
            }

            if (modelDir is null)
                continue;
            var full = Path.GetFullPath(Path.Combine(modelDir, location));
            var info = new FileInfo(full);
            if (!info.Exists)
            {
                report.Findings.Add(new Finding("OX002", Severity.Low, "External data file missing", $"'{location}' (for {tensors}) is not next to the model.", $"external_data:{location}"));
                continue;
            }
            var target = info.LinkTarget is null ? null : info.ResolveLinkTarget(returnFinalTarget: true)?.FullName;
            if (target is not null && !target.StartsWith(modelDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                report.Findings.Add(new Finding("OX001", Severity.Critical, "External data is a symlink out of the model folder",
                    $"'{location}' links to {target}. This bypasses the onnx path checks (CVE-2026-27489, CVE-2026-34447) to read arbitrary files.", $"external_data:{location}"));
        }
    }

    /// <summary>A bounds-checked protobuf wire-format reader that skips large fields without reading them.</summary>
    sealed class ProtoReader(Stream stream)
    {
        public delegate void FieldHandler(int field, int wire, long start, long end);

        public void Message(long start, long end, int depth, FieldHandler handler)
        {
            if (depth > MaxDepth * 4) throw new InvalidDataException("Messages nested too deeply");
            var pos = start;
            while (pos < end)
            {
                stream.Position = pos;
                var tag = Varint(end);
                var field = (int)(tag >> 3);
                var wire = (int)(tag & 7);
                long valueStart, valueEnd;
                switch (wire)
                {
                    case 0: Varint(end); valueStart = valueEnd = stream.Position; break;
                    case 1: valueStart = stream.Position; valueEnd = valueStart + 8; break;
                    case 5: valueStart = stream.Position; valueEnd = valueStart + 4; break;
                    case 2:
                        var length = (long)Varint(end);
                        valueStart = stream.Position;
                        valueEnd = valueStart + length;
                        if (length < 0 || valueEnd > end) throw new InvalidDataException($"Field {field} length {length:N0} runs past its message");
                        break;
                    default: throw new InvalidDataException($"Unsupported wire type {wire} at offset {pos}");
                }
                if (valueEnd > end) throw new InvalidDataException("Field runs past its message");
                handler(field, wire, valueStart, valueEnd);
                pos = valueEnd;
            }
        }

        public string String(long start, long end)
        {
            if (end - start > MaxStringBytes) return $"<{end - start:N0} bytes>";
            var bytes = new byte[end - start];
            stream.Position = start;
            stream.ReadExactly(bytes);
            return Encoding.UTF8.GetString(bytes);
        }

        ulong Varint(long end)
        {
            ulong value = 0;
            for (var shift = 0; shift < 64; shift += 7)
            {
                if (stream.Position >= end) throw new EndOfStreamException("Truncated varint");
                var b = stream.ReadByte();
                if (b < 0) throw new EndOfStreamException("Truncated varint");
                value |= (ulong)(b & 0x7F) << shift;
                if ((b & 0x80) == 0) return value;
            }
            throw new InvalidDataException("Varint too long");
        }
    }
}
