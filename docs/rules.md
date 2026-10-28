# Rule reference

Every finding has a stable rule ID. Severity can vary within a rule (for example T005 is Medium for a
trigger alone and High when the template also carries a payload); the table gives the typical range.

Exit codes: `0` no findings above Info, `1` Low/Medium, `2` High/Critical, `3` scan error.

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
| T004 | Medium–High | Instruction-like text: hiding instructions from the user, overriding rules, shell/download commands, secrets |
| T005 | Info–High | The template branches on a phrase in the conversation (Medium alone, High with a payload or when T013 confirms it) |
| T006 | Info–High | Date/time/randomness in a condition (time bombs); Info when the date is only printed |
| T007 | Medium–Critical | Invisible Unicode in the template |
| T008 | Medium | Very large template, or one that could not be fully parsed |
| T009 | Info | Fixed text the template adds, quoted for review |
| T010 | Info–Medium | Comparison with 62 official templates (current and earlier versions): exact match, earlier version, different version, or a near copy with added text (shown) |
| T011 | Medium | Possible resource exhaustion (`**`, numbers ≥ 10⁸) |
| T013 | Info–High | **Rendered evidence**: the sandbox renderer (Jinja or Ollama's Go templates) shows the template adds text when a trigger phrase or date is present |
| T014 | Info | The template could not be rendered in the sandbox (static checks still apply) |

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
| H004 | Info | Header-only read statistics, or files not checked |
| H005 | Medium–High | A GGUF's template differs from the one Hugging Face displays, or quants disagree |
| H006 | Info–Low | Abliterated / merged / uncensored lineage |
| H007 | Low–Medium | Publisher is not an official lab or established quantizer |
| H008 | Medium | New repo with very high downloads; card impersonating an official org |
| H009 | Medium | Pickle-based weight files in the repo |
| P001 | Info | Ollama registry provenance |
| P002 | Low | Source repo or file no longer on Hugging Face |
| P003 | Info–High | Local file vs published file (size; sha256 with `--hash`) |
| W001 | Medium–High | Template or system prompt changed without a model update |
| W002 | Info | Model updated, with a different template |
| W003 | Info | Model added or removed since the baseline |
