# Rule reference

Every finding has a stable rule ID. Severity can vary within a rule (for example T005 is Medium for a
trigger alone and High when the template also carries a payload); the table gives the typical range.

Exit codes: `0` no findings above Info, `1` Low/Medium, `2` High/Critical, `3` scan error.

`D001` (Info) records batch download plans, model sets excluded by the size limit, and companion-file coverage.
Download failures use the report's `error` field and exit code 3. See [batch scanning](batch.md).

## Model files (layer 1)

| ID | Severity | What it means |
|---|---|---|
| S001 | Medium–High | Not a GGUF file, unsupported version, or big-endian |
| S002 | Critical | Header declares more metadata entries or tensors than the file can hold |
| S003 | High–Critical | A declared string/array length runs past the end of the file, or an unknown value type |
| S004 | Medium–Critical | Tensor has more than 4 dimensions, or an empty dimension |
| S005 | High–Critical | Tensor shape overflows, or the row is not a whole number of quantization blocks |
| S006 | Medium | Unknown tensor type |
| S007 | High | Tensor offset is not aligned |
| S008 | Critical | Tensor data extends beyond the file (the "Bleeding Llama" class, CVE-2026-7482) |
| S009 | Critical | Two tensors overlap |
| S010 | High | Duplicate metadata key or tensor name (different runners may read different copies) |
| S011 | Low–Medium | Unused gap between tensors |
| S012 | Low–Medium | Data after the last tensor |
| S013 | High | Invalid `general.alignment` |
| M001 | Medium–High | Very large metadata string |
| M002 | Medium | Base64-looking high-entropy blob in metadata |
| M003 | High | Executable or archive signature in metadata or unused space |
| M004 | Info–Low | URL in metadata |
| M005 | Medium–Critical | Invisible Unicode in metadata (tag characters are decoded and shown) |
| M006 | Info | Metadata keys outside the standard namespaces |
| K001 | Low–High | Special token id outside the vocabulary |
| K002 | High | Vocabulary larger than the embedding table |
| K003 | Medium–High | A control/user-defined token whose text is an instruction, link or sentence |
| F001 | High–Critical | safetensors header length is impossible |
| F002 | Low–High | safetensors header is not valid JSON, or an entry is malformed |
| F003 | Medium | Unknown safetensors dtype |
| F004 | High–Critical | safetensors tensor outside the data section, or size does not match shape |
| F005 | Critical | Overlapping safetensors tensors |
| F006 | Low–Medium | Unused bytes in a safetensors file |
| OX001 | High–Critical | ONNX external data outside the model folder: absolute path, `..`, or a symlink (CVE-2022-25882, CVE-2024-27318, CVE-2026-27489) |
| OX002 | Low | ONNX external data file missing |
| OX003 | Medium | ONNX custom operator domains (need native custom-op libraries) |
| OX004 | Info | ONNX model summary |
| OX005 | Medium | ONNX file could not be fully parsed |
| PK001 | Critical | Pickle imports something that runs code on load (`os.system`, `builtins.eval`, `subprocess`, …) |
| PK002 | Medium | Pickle imports objects outside the usual torch/numpy rebuild functions |
| PK003 | Medium | Pickle could not be fully analysed |
| PK004 | Info | Pickle-based weights (prefer safetensors or GGUF) |

## Chat templates (layer 2)

| ID | Severity | What it means |
|---|---|---|
| T001 | Info | Template found (sha256 shown; `--dump-template` prints it) |
| T002 | High–Critical | Jinja sandbox-escape building blocks (`__globals__`, `__subclasses__`, `lipsum`, `|attr`, `include`, …) — CVE-2024-34359, CVE-2026-5760 |
| T003 | Low–High | URLs (Low) or markup that fetches a URL when rendered (High) |
| T004 | Low–High | Instruction-like text: hiding instructions from the user, overriding rules, shell/download commands, secrets, covert actions ("silently append…"). A covert word with no such action ("moves silently", common in role-play personas) is Low |
| T005 | Info–High | The template branches on a phrase in the conversation (Medium alone, High with a payload or when T013 confirms it) |
| T006 | Info–High | Date/time/randomness in a condition (time bombs); Info when the date is only printed |
| T007 | Medium–Critical | Invisible Unicode in the template |
| T008 | Medium | Very large template, or one that could not be fully parsed |
| T009 | Info | Fixed text the template adds, quoted for review |
| T010 | Info–Medium | Comparison with 62 official templates (current and earlier versions): exact match, earlier version, different version, or a near copy with added text (shown) |
| T011 | Medium | Possible resource exhaustion (`**`, numbers ≥ 10⁸) |
| T013 | Info–High | **Rendered evidence**: the sandbox renderer (Jinja or Ollama's Go templates) shows the template adds text when a trigger phrase or date is present |
| T014 | Info | The template could not be rendered in the sandbox (static checks still apply) |
| T015 | Info–Medium | `--classifier`: a local prompt-injection model rates template or system-prompt text as injection. Info alone (it flags ordinary instructions too); Medium when a trigger (T005/T013) or an injected-looking copy (T010) corroborates it |

## Runner, network and agent (layers 3–5)

| ID | Severity | What it means |
|---|---|---|
| O001 | High | Malformed layer digest in an Ollama manifest (path traversal guard) |
| O002 | Low | Ollama manifest references a missing blob |
| O003 | Info | Ollama's template layer overrides the GGUF's template |
| O004 | Medium | Oversized Ollama template/system layer |
| O005 | Info | Ollama formats prompts with a built-in renderer/parser |
| A001 | High–Critical | Installed runner version has a known vulnerability (data/runner-vulns.json) |
| A002 | High | `OLLAMA_HOST` listens beyond loopback |
| A003 | High | `OLLAMA_ORIGINS=*` |
| A004 | Medium–High | A model server port is open to the network (process named) |
| A005 | High | Docker publishes a model server port on all interfaces (bypasses ufw) |
| A006 | Info–Critical | `--probe`: the server answers on the LAN without authentication |
| A007 | Info | Runner detected |
| A008 | Info | MCP tool configured for a local-model client, with its powers |
| A009 | Info–Critical | Windows: a staged Ollama update installer is not validly signed (Critical) or signed by someone other than Ollama (High) |
| G001 | High | Secrets an agent can read (values never printed) |
| G002 | Info–Critical | Overall risk, per layer, with escalation when layers combine |
| G003 | Info | Privilege-separation guidance |
| G004 | Medium–High | Tool combinations: file/shell + network, file tool on the whole home directory, shell alone |

## Provenance and drift

| ID | Severity | What it means |
|---|---|---|
| H001 | Info | Publisher, dates, downloads, lineage |
| H002 | Medium–High | Executables, scripts, Python or archives in a model repo |
| H003 | Medium–High | Model card tells you to run something, disable security software, or use `trust_remote_code` |
| H004 | Info–Low | Header-only read statistics, files not checked, or files that need HF_TOKEN (gated) |
| H005 | Medium–High | A GGUF's template differs from the one Hugging Face displays, or quants disagree |
| H006 | Info–Low | Abliterated / merged / uncensored lineage |
| H007 | Low–Medium | Publisher is not an official lab or established quantizer |
| H008 | Medium | New repo with very high downloads; card impersonating an official org |
| H009 | Medium | Pickle-based weight files in the repo |
| H011 | Info–High | Model card copied from an official repo: Info when the source is declared or credited, Medium when not, High when the repo also ships executables or run-this instructions |
| P001 | Info | Ollama registry provenance |
| P002 | Low | Source repo or file no longer on Hugging Face |
| P003 | Info–High | Local file vs published file (size; sha256 with `--hash`) |
| W001 | Medium–High | Template or system prompt changed without a model update |
| W002 | Info | Model updated, with a different template |
| W003 | Info | Model added or removed since the baseline |

## Policy

| ID | Severity | What it means |
|---|---|---|
| PL001 | Low | A suppression in the policy file has expired: it no longer applies and the findings it covered count again |
| PL002 | Info | A suppression matched no finding in this run (a stale entry to remove) |

## Policy files

A team can commit a `.modelcheck.yml` (or `.modelcheck.yaml` / `.modelcheck.json`). Every command (scan, local,
repo, audit, watch, batch) uses the first one found in the current directory or its parents. Use `--policy <file>`
to choose one, or `--no-policy` to ignore it. `modelcheck policy init` writes a commented starter, and
`modelcheck policy check [file]` validates one. It lists each suppression with its expiry and exits 1 if any have
expired, or 3 if the file is invalid.

```yaml
version: 1
fail-on: high            # counting findings at or above this exit 2: info|low|medium|high|critical|never

allow:                   # provenance findings (H006-H008, H011, P001-P003) for these become Info
  publishers: [meta-llama, library]     # HF org / Ollama namespace ("library" = official Ollama models)
  models:
    - hf:Qwen/Qwen2.5-*                 # matched against the target, or the local file path

severity:                # per-rule overrides; rule ids may be globs; "off" drops the finding
  T009: low
  P002: off

suppress:                # accepted findings; kept in JSON/SARIF, not counted
  - rule: H007
    target: "hf:my-org/**"              # optional, default ** (everything)
    location: general.base_model        # optional
    reason: Fine-tune of our own model; reviewed in TICKET-123   # required
    expires: 2027-03-31                 # required (yyyy-MM-dd); after this date: PL001

baseline: .modelcheck-baseline.json     # relative to the policy file
```

The policy is applied in this order:

1. Severity overrides.
2. Allow-lists.
3. Suppressions. A suppression applies through its `expires` date.
4. The baseline.

Globs are case-insensitive. `*` matches within one `/` segment and `**` matches across segments. `?` matches one
character, and `\` is treated as `/`.

The policy file accepts this subset of YAML:
- block mappings and sequences;
- `[a, b]` lists;
- quoted and plain strings;
- `#` comments.

Anchors, tags, block scalars and `{...}` maps are rejected with the line number.

**Baselines** let CI fail only on new findings. To record the current findings, add `--write-baseline <file>` to any
command (or run `modelcheck baseline write <file> <paths>`). That run exits 0 unless a scan errors. Later runs with
the baseline (`baseline:` in the policy, or `--baseline-file`) work like this:
- Findings already recorded are marked `existing`. Text output shows them as KNOWN and hides them unless you pass
  `--show-suppressed`.
- Other findings are marked `new`.
- Only new findings count toward the exit code.

A finding's fingerprint is made from four parts:
- the rule;
- the target, relative to the current directory and with `/` separators;
- the location;
- the title, with digits masked.

Wording in the detail and changed counts do not break a match. Suppressed findings are not written to a baseline.

Output: in JSON/JSONL, a suppressed finding has `"suppression": "<reason> (policy suppress[i], until <date>)"`, and
with a baseline each finding has `"baseline": "new"|"existing"`. In SARIF they become `suppressions` (kind
`external`, status `accepted`, with the justification) and `baselineState` (`new`/`unchanged`), so GitHub code
scanning shows them correctly. `--min-severity` still only changes what is displayed; the exit code is computed
from every finding that counts.

## Weight lineage

`modelcheck lineage <model.gguf> --base <gguf>` and `modelcheck repo <repo> --lineage` check whether a GGUF really is
a quantization of the model it claims. Both take local files, `hf:org/repo/file.gguf` or HTTPS URLs, and remote files
are read with Range requests (headers plus about 16K values per tensor: ~10-20 MiB for a 0.5B model).

For every tensor both files share, the same rows are dequantized (F32, F16, BF16, Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, Q4_K,
Q5_K, Q6_K, Q8_K). The difference is then divided by the quantization step at each value. Rounding to the nearest level
leaves an RMS of about 0.29 (1/√12) whatever the type, so a real quantization of the same weights measures about 0.29.
Edited weights measure well above 0.6 at the same tensors.

Measured on Qwen2.5-0.5B-Instruct:
- **Genuine quants** (official and bartowski Q4_K_M/Q8_0 against a direct F16 conversion) measure 0.27–0.42.
- **An abliterated fine-tune** (Josiefied) measures 1.1–7.3 on exactly the 49 tensors abliteration touches
  (`attn_output` and `ffn_down` in every layer, plus `token_embd`).
- **The cosine of the abliterated tensors** stays above 0.99, so plain similarity metrics miss this.

| ID | Severity | What it means |
|---|---|---|
| L001 | High | Weights differ from the claimed base beyond quantization noise: lists the changed tensors and a per-layer table. Fine-tuned, merged, abliterated or otherwise edited |
| L002 | High | Weights are not derived from the claimed base (most tensors uncorrelated, or shapes differ) |
| L003 | Info | Weights match the base within quantization noise |
| L004 | Info–Low | Tensors not compared (unsupported types such as Q2_K/Q3_K/IQ*, or missing), or no base GGUF found for `repo --lineage` |
| L005 | Medium | Inconclusive: one file is an activation-aware (AWQ-style) conversion |

A match proves the sampled weights are the base's up to quantization. A mismatch shows modification, not malice:
most derivatives are honest fine-tunes.

**AWQ conversions (L005).** Some labs' own GGUFs are not direct conversions. For example, Qwen's official
`Qwen2.5-*-GGUF` files differ from Qwen's published safetensors:
- norm weights are divided by per-channel scales;
- the next matrices are multiplied by the same scales;
- outlier weights are clipped.

That is AWQ scale migration. modelcheck fits per-row and per-column scales to recognise it. The clipping, though,
changes weights about as much as light edits do. So when a quarter or more of the tensors are rescaled, the
comparison reports L005 rather than L001 or L003. Compare against a direct F16/BF16/Q8_0 conversion of the published
safetensors instead. `repo --lineage` looks for one at `ggml-org/<name>-GGUF` before the lab's own `<base>-GGUF`.
