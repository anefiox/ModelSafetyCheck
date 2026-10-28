# ModelSafetyCheck — Build Plan

Open-source, cross-platform scanner for local-AI setups. It treats a local model setup as
five layers, each with its own threat model:

| Layer | What | Threat examples | Command |
|---|---|---|---|
| L1 | The model file (GGUF) | Malformed headers that exploit runner parsers (e.g. "Bleeding Llama" lying tensor sizes), payloads hidden in metadata or slack space | `scan`, `local` |
| L2 | The chat template (Jinja inside the GGUF, or overridden by the runner) | SSTI → RCE (llama-cpp-python "Llama Drama" CVE-2024-34359, SGLang 2026), poisoned templates with trigger-activated hidden instructions (Pillar Security), template rewritten after install via the runner API | `scan`, `local`, `watch`, `repo` |
| L3 | The runner (Ollama, LM Studio, llama.cpp, vLLM, SGLang) | Known-vulnerable versions, unsigned auto-update, path traversal | `audit` |
| L4 | The port / network exposure | `OLLAMA_HOST=0.0.0.0`, Docker `-p` bypassing ufw, no auth, DNS rebinding | `audit` |
| L5 | Weights + tools (agents) | Backdoored fine-tunes with trigger phrases (ProjectDiscovery), abliterated/merged models with unknown lineage, secrets reachable by the agent | `repo`, `audit --agent-dir` |

**Non-goal / honesty statement (must be in README):** weight backdoors cannot be detected by static
scanning. A clean result means "no known file/template/setup issue found", never "this model is safe".
The tool reduces blast radius and surfaces provenance; it does not certify weights.

## Principles

- **Never execute untrusted content.** Templates are lexed/parsed and analysed, never rendered by a
  real Jinja engine. Repo scripts are never run.
- **Never trust a size field.** Every length/count/offset is validated against the bytes actually
  remaining before use. Hard caps on everything.
- **Offline by default.** Nothing leaves the machine unless `--online` (or the `repo` command) is used.
- **Low false-positive rate.** Malicious templates are rare (~1 in 5,400 in a 2026 HF-wide scan, all PoCs),
  so unknown ≠ malicious. Known-good template DB + readable diffs over alarms.
- **Data, not code, for vulnerability info.** Vulnerable runner version ranges live in versioned JSON
  sourced from real advisories, updatable without a release.
- **CI friendly.** Exit codes `0` clean, `1` warnings, `2` high/critical, `3` tool error. JSON + SARIF output.

## Tech stack

- C# / .NET 10, Native AOT single-file binaries: win-x64, win-arm64, linux-x64, linux-arm64, osx-arm64.
- `System.CommandLine` for the CLI. No other runtime dependencies in Core.
- xUnit tests; SharpFuzz for parser fuzzing.
- MIT licence.

## Solution layout

```
src/
  ModelSafetyCheck.Core       GGUF parser (strict, span-based, memory-mapped, hard limits)
  ModelSafetyCheck.Jinja      Jinja lexer/parser for analysis only (never renders)
  ModelSafetyCheck.Rules      IRule, Finding, Severity, rule implementations, scan engine
  ModelSafetyCheck.Local      Discovery of installed models (Ollama, LM Studio, llama.cpp cache)
  ModelSafetyCheck.Cli        `modelcheck` executable, output formatters
tests/
  ModelSafetyCheck.Tests      Unit tests + generated malicious fixtures (GgufWriter)
data/
  known-templates.json        Hashes of official chat templates (phase 2)
  runner-vulns.json           Vulnerable runner version ranges (phase 2)
```

## Feature checklist

Status: `[ ]` todo · `[~]` partial · `[x]` done. Every rule has a stable ID.

### Phase 1 — MVP: `scan` + `local`

Core parser
- [x] P-01 Read-only, bounds-checked stream reader (every read checked against bytes remaining; stream-based so the same parser works over HTTP Range for `repo`)
- [x] P-02 Parse header: magic, version (1–3; v1 uses 32-bit counts), tensor count, KV count
- [x] P-03 Parse all KV types incl. nested arrays (with depth limit)
- [x] P-04 Parse tensor infos (name, n_dims, dims, type, offset)
- [x] P-05 Hard limits: string length, array length, KV count, tensor count, nesting depth
- [x] P-06 Parser never throws on hostile input — returns structured parse errors as findings
- [x] P-07 Compute tensor data start (alignment from `general.alignment`, default 32)

Structural rules (GGUF-S)
- [x] S001 Bad magic / unsupported version
- [x] S002 Counts impossible for file size
- [x] S003 String/array length exceeds remaining bytes (parse failure)
- [x] S004 n_dims > 4 or zero dimension
- [x] S005 Element count overflow (product of dims)
- [x] S006 Unknown tensor type
- [x] S007 Tensor offset not aligned
- [x] S008 Tensor data extends beyond end of file (Bleeding Llama class)
- [x] S009 Overlapping tensors
- [x] S010 Duplicate KV keys / duplicate tensor names
- [x] S011 Unexplained gap between tensors (> alignment padding)
- [x] S012 Trailing data after last tensor
- [x] S013 Invalid alignment value (not power of two / zero)

Metadata rules (GGUF-M)
- [x] M001 Oversized string values
- [x] M002 High-entropy / base64-looking blobs
- [x] M003 Executable signatures inside strings or slack space (MZ, ELF, PK, `#!`, Mach-O)
- [x] M004 URLs in metadata (info)
- [x] M005 Invisible / bidi / Unicode tag characters in any string
- [x] M006 Unknown top-level key namespaces (info)

Template rules (GGUF-T) — applied to `tokenizer.chat_template` and every `tokenizer.chat_template.*`
- [x] T001 Template present / extracted (info, with SHA-256)
- [x] T002 Jinja sandbox-escape primitives (`__class__`, `__globals__`, `__subclasses__`, `__builtins__`,
          `__mro__`, `__init__`, `__import__`, `lipsum`, `cycler`, `joiner`, `config`, `self`, `request`, `os`, `popen`, `eval`, `exec`)
- [x] T003 URLs, HTML/script/img/iframe tags, markdown image links in template literals
- [x] T004 Imperative / concealment instruction phrases in literals ("do not tell the user", "always include", "ignore previous", …)
- [x] T005 Content-based triggers: conditions that test message content for literal strings
- [x] T006 Time/date/random based conditions (`strftime_now`, `now`, `random`)
- [x] T007 Invisible Unicode inside the template
- [x] T008 Template lex failure / unusually large template
- [x] T009 Fixed natural-language text the template adds (info, quoted so the user can read what the model is told)
- [x] T011 Resource exhaustion: `**` or numeric literals ≥ 1,000,000 (render-time DoS on every prompt)
- [x] T010 Known-good / unknown template (see D-02)
- [x] T012 Closed as not statically checkable: every chat template inserts message text verbatim, so whether `<|im_start|>system` inside untrusted text becomes a real control token depends on how the runner tokenizes the rendered prompt, which needs a running model to test. Documented as a hardening item (docs/hardening.md, layer 5) instead of a rule that would fire on every template

Tokenizer rules (GGUF-K)
- [x] K001 BOS/EOS/PAD/UNK ids out of vocabulary range
- [x] K002 Vocab size ≠ embedding tensor dimension
- [x] K003 Special/added tokens whose text looks like instructions (see phase 2)

Local discovery (`local`)
- [x] L-01 LM Studio model dirs (`~/.lmstudio/models`, `~/.cache/lm-studio/models`)
- [x] L-02 Ollama store (`OLLAMA_MODELS` or `~/.ollama/models`): read manifests, resolve GGUF blob
- [x] L-03 Ollama **template layer** (`application/vnd.ollama.image.template`) scanned with GGUF-T rules — this is the template that actually runs
- [x] L-04 Ollama system-prompt layer (`application/vnd.ollama.image.system`) scanned with T003/T004/T007
- [x] L-05 O003 Info when the Ollama template layer overrides the GGUF's embedded one (different dialects, so no text diff; both are scanned)
- [x] O001 Malformed layer digest in a manifest (path traversal guard; layer not opened)
- [x] O002 Manifest references a missing blob
- [x] O004 Oversized template/system layer
- [x] L-09 Ollama projector and adapter layers scanned as GGUF too
- [x] L-06 llama.cpp cache (`LLAMA_CACHE`, platform default)
- [x] L-07 Hugging Face hub cache `.gguf` files
- [x] L-08 LM Studio per-model prompt-template overrides (user config under `~/.lmstudio/.internal/`) — these replace the embedded template the same way Ollama's layer does
- [x] L-10 Ollama `renderer`/`parser` built-in formatting noted (O005)

CLI / output
- [x] C-01 `modelcheck scan <path...>` (files or directories, recursive)
- [x] C-02 `modelcheck local`
- [x] C-03 Text output with severity colours
- [x] C-04 `--format json`
- [x] C-05 `--dump-template` prints extracted templates
- [x] C-06 Exit codes 0/1/2/3
- [x] C-07 `--min-severity` filter
- [x] C-08 `--format sarif`
- [x] C-09 Native AOT publish verified on win-x64 (4.8 MB single exe, no trim/AOT warnings). On Windows the link step needs the VS C++ build tools and `vswhere.exe` on PATH (`C:\Program Files (x86)\Microsoft Visual Studio\Installer`)

Testing
- [x] X-01 `GgufWriter` test helper that can write valid and deliberately malformed files
- [x] X-02 One fixture per structural rule
- [x] X-03 Malicious template fixtures (SSTI, trigger, hidden instruction, unicode tags)
- [x] X-04 Clean template fixtures from real model families (no false positives) — ChatML/Qwen, Llama 3, Mistral, Gemma, SmolLM3 mode switches, Ollama Go template; also verified clean on a real Gemma 4 12B GGUF
- [x] X-06 False-positive corpus: see phase 2 X-06
- [x] X-07 CI matrix workflow written (ubuntu/windows/macos); not run yet
- [x] X-05 Fuzzing: see phase 2 X-05

### Phase 2 — `audit`, reference data, releases

Reference data (`data/`, embedded; a newer copy in `~/.modelcheck/data` or `$MODELCHECK_DATA` overrides it)
- [x] D-01 `known-templates.json`: 50 templates (41 distinct) from 50 official/established repos — Qwen 2.5/3/Coder/QwQ, DeepSeek R1/V3, Phi 3.5/4, GPT-OSS, Gemma 2/3/3n/4, Llama 3/3.1/3.2/3.3/4, Mistral/Nemo/Small/Devstral, Granite, SmolLM, OLMo, GLM, Kimi K2, LFM2, Nemotron, Command R
- [x] D-02 T010: exact match → Info; ≥85% similar copy with added prose lines → Medium (shows added lines, prose first); larger differences → Info "different version"; no match → Info
- [x] D-03 Whitespace-insensitive normalised hash
- [x] D-04 `tools/TemplateDbBuilder` regenerates the DB from `data/template-sources.json` (HF_TOKEN optional). Version = build date
- [x] D-05 `runner-vulns.json`: CVE-2026-7482 Bleeding Llama (<0.17.1), CVE-2026-42248/42249 Windows updater (0.12.10–<0.23.0, **fix version only third-party reported**, marked `confidence: reported`), Ollama desktop drive-by 2025 (0.10.0, fixed 0.10.1, no CVE), CVE-2024-37032 (<0.1.34), CVE-2024-28224 (<0.1.29), CVE-2024-34359 llama-cpp-python (0.2.30–<0.2.72), CVE-2026-5760 SGLang (<0.5.11, reported). Each entry lists its sources
- [x] D-06 Exact match with an official template downgrades heuristic hits to Info (official templates contain e.g. "do not tell the user about function calls"; injected text breaks the exact match)
- [x] D-07 Historical template versions: `TemplateDbBuilder --history` reads template files at the last 12 commits and the GGUF header of up to 3 earlier uploads per GGUF repo (Range requests at the old revision). 26 earlier versions in the DB (62 distinct templates); T010 reports "earlier version" with revision and date. Your local Gemma 4 Q4_K_M now matches revision e38afa56ee (2026-06-04) exactly. `--only org/repo` merges a single source; the weekly workflow runs with `--history`
- [x] D-08 `.github/workflows/template-db.yml`: weekly rebuild + official-template test + PR on change (HF_TOKEN secret optional). Not run yet

`audit` command
- [x] A-01 Runner detection: Ollama (running server `/api/version`, else CLI), LM Studio (`historical-version-info.json`), llama-cpp-python / SGLang / vLLM (first Python on PATH only; other venvs are not seen)
- [x] A-02 A001 version matching against `runner-vulns.json`, platform-aware, with fix text and sources
- [x] A-03 A002 `OLLAMA_HOST` exposure + A003 `OLLAMA_ORIGINS=*`: process env, Windows user/machine env, systemd units and drop-ins (system + user), `/etc/environment`, `launchctl getenv`
- [x] A-04 A004 non-loopback listeners on 11434/1234/30000 (High) and 8080/8000/5001 (Medium); `lsof` fallback where .NET can't list listeners
- [x] A-05 A005 Docker containers publishing AI ports on 0.0.0.0/:: (ufw bypass note on Linux)
- [~] A-06 LM Studio: `lms server status --json` gives running state and port; a server on a non-default port is now added to the exposure check (A004/A006) and named in A007. The network/auth toggles themselves are still not read (undocumented config); exposure is measured from sockets and the probe instead. The `port` field name is unverified (server was not started during development; falls back to 1234)
- [x] A-07 A006 `--probe`: unauthenticated request to exposed servers via this machine's own LAN addresses
- [~] A-08 Ollama Windows auto-update: covered by the CVE-2026-42248 entry's remediation (the setting itself is not read)
- [x] A-09 Every network/runner finding includes a "Fix:" line
- [x] A-10 Port owner via netstat (Windows) / ss (Linux) / lsof (macOS); named in A004. Shared ports (8000/8080/5001) owned by clearly unrelated processes (nginx, node, …) are no longer reported
- [x] A-11 MCP tools (LM Studio `mcp.json`, AnythingLLM, `--mcp-config` for any other client): A008 per tool with shell/files/network powers; G004 High for file/shell + network together, High for a file tool on the whole home/drive, Medium for shell alone; folders a file tool can read get the G001 secret scan. Env values never read into the report. Feeds the L5 rating

Agent risk (`audit --agent-dir <path>`)
- [x] G-01 G001 secrets by file name (.env*, SSH keys, key stores, .netrc, .git-credentials, cloud creds, tfstate) and content (private keys, AWS, GitHub, OpenAI, Anthropic, Slack, Google, Stripe, HF, npm tokens, credentials in URLs incl. `.git/config`). Values are never printed
- [x] G-02 G002 per-layer rating L1–L5 with escalation (exposed + vulnerable runner; exposed + readable secrets)
- [x] G-03 Privilege-separation guidance

Other
- [x] K003 Control/user-defined tokens containing instructions, invisible characters, URLs or sentences (parser keeps `tokenizer.ggml.token_type`)
- [x] L-06 / L-07 llama.cpp and Hugging Face hub caches (symlinks de-duplicated)
- [x] L-08 LM Studio per-model overrides and presets: prompt templates (Jinja) and system prompts scanned
- [x] L-10 O005 Ollama config `renderer`/`parser` noted (formatting code not on disk)
- [x] C-08 `--format sarif` (SARIF 2.1.0 with `security-severity` for GitHub code scanning)
- [x] X-05 Fuzzing: mutation test in the suite (3 × 3,000 files) plus a coverage-guided libFuzzer campaign (SharpFuzz 2.3.0 + libfuzzer-dotnet, Core/Jinja/Rules instrumented, whole scan pipeline incl. both renderers): 2.26M executions in 5 minutes, 14,743 coverage features, no crashes. The minimized corpus (1,095 inputs, 345 KB zip) is a regression test (FuzzCorpusTests)
- [x] X-06 False-positive benchmarks: (1) every official template in the DB analyses clean; (2) `tools/TemplateCorpus` analyses the templates of the 1,000 most-downloaded GGUF repos via the Hub API (no downloads). First run: 36% of 352 distinct templates warned; after tuning (dangerous-dunder list, concealment phrasing, trigger needs a payload for High, emoji-aware variation selectors, src-only active markup, URL-only = Low, comment/markup-aware T010 prose) it is 6.5% at Low+, ~4% at Medium+, and the rest are genuinely unusual (content-routing templates, new default system prompts)
- [x] X-07 CI on ubuntu/windows/macos (`.github/workflows/ci.yml`). Not run yet (no remote)
- [x] R-01 `.github/workflows/release.yml`: tag `v*` → Native AOT for win-x64, win-arm64, linux-x64, linux-arm64, osx-arm64 + SHA256SUMS → GitHub release. Not run yet
- [x] R-02 `dotnet pack` → `ModelSafetyCheck` dotnet tool (portable); `dotnet publish -r <rid>` → native single binary. Both verified locally
- [x] R-03 `.gitattributes` normalises line endings

### Phase 3 — `repo` + `watch`

`repo <org/name | URL>...` (`--max-files`, `--all-files`, `--budget-mb`)
- [x] H-01 HF API with `?blobs=true` (files, LFS sha256, tags, cardData, displayed GGUF template). HF_TOKEN is sent only to huggingface.co
- [x] H-02 Executables/scripts (High), Python (Medium), archives (Medium)
- [x] H-03 README lures: run .bat/.ps1/.exe/scripts, pipe-to-shell, encoded PowerShell, disable AV, `trust_remote_code`, hidden characters. High for unknown publishers, Medium for official/quantizers
- [x] H-04 Header-only GGUF scan via `HttpRangeStream` (1 MiB blocks, budget cap). ~16 MiB read for a 7–12 GB Gemma 4 file. Split GGUFs: first shard only. Default 6 files spread across sizes
- [x] H-05 File template vs HF-displayed template (High if the file's template also has warnings, else Medium = likely a stale upload); differing templates across files. Also scans `chat_template.jinja` / `tokenizer_config.json` in non-GGUF repos
- [x] H-06 Lineage from `base_model:*` tags and card; abliterated/merge/uncensored markers
- [x] H-07 Publisher tier from `data/trusted-publishers.json`
- [x] H-08 New repo with >50k downloads; card naming an official org ≥3 times with no base model (impersonation)
- [x] H-09 Pickle formats → picklescan/safetensors advice
- [x] H-10 `local --online [--hash]`: LM Studio paths, HF-cache paths and `ollama:hf.co/...` models mapped to their repo; publisher/lineage (H001/H006/H007); P003 size check (Low = older download), optional sha256 (Info match / High same-size mismatch); P002 repo or file gone; P001 Ollama registry note. Verified on this machine: Gemma 4 Q4_K_M is an older upload, mmproj sha256 matches
- [x] H-11 H011 card copy check for unknown publishers: 5-word-shingle containment against declared base models, official repos the card links to, and `<official-org>/<same-name>` for orgs the card mentions. Undeclared copy = Medium (High with executables or run-this instructions: the fake 'Privacy Filter' pattern); copy that declares or credits its source ("Original model: <link>") = Info. Verified on RichardErkhov/Qwen_-_Qwen2.5-7B-Instruct-gguf (100% copy, credited → Info) and a fake-hub reconstruction of the Privacy Filter case (High)

`watch` (`--baseline`, `--update`, `--store`, `--log`, `--print-schedule`, `--install-schedule`)
- [x] W-01 Snapshot store `~/.modelcheck/snapshots.json`: target → weights fingerprint (Ollama blob digest / file size+mtime) + sha256 of every template and system prompt
- [x] W-02 First run saves a baseline; later runs report changes; `--update` accepts them
- [x] W-03 W001 High: template/system prompt changed or added with unchanged weights; W001 Medium for LM Studio override changes; W002 Info for model updates; W003 Info for added/removed models
- [x] W-04 Schedule plans: Windows `schtasks` hourly, systemd user timer, launchd agent. `--print-schedule` verified on Windows; `--install-schedule` not run here because it changes the system
- [x] W-05 `watch --notify` (on by default in scheduled runs): Windows toast via PowerShell, `osascript` on macOS, `notify-send` on Linux. Model names are passed via environment variables, never spliced into the script. Toast script syntax-checked; not shown on screen during development

### Phase 4

- [x] F-01 `action.yml` (composite): downloads the release binary for the runner (checksum-verified against SHA256SUMS), runs `scan` or `repo`, uploads SARIF to code scanning, `fail-on: high|low|never`. Not run yet (needs a published release)
- [x] F-02 Safe Jinja renderer (`ModelSafetyCheck.Jinja/Render`): own parser + interpreter, plain data only (no reflection/IO/process), names starting with `_` always undefined, caps on steps (2M), output (2M chars) and macro depth (64); HF-compatible `trim_blocks`/`lstrip_blocks`, `tojson`, `raise_exception`, `strftime_now`, loop controls, namespaces, macros, filter blocks, `{% generation %}`.
  - [x] `modelcheck explain <gguf|tokenizer_config.json|template>` [--messages file.json]: exact prompt for a sample conversation, with a tool, and every trigger probe that changed the prompt
  - [x] T013 rendered evidence: each phrase/word/date the template compares against is put into the user and system message (and the clock moved for `strftime_now`); a word-level LCS diff shows only template-added text. Prose/links = High (also raises T005 to High); formatting-only = Info. T014 Info when a template cannot be rendered
  - [x] Coverage: 41/41 official templates render; 337/352 (96%) distinct templates of the top 1,000 GGUF repos (the rest mostly reject the sample conversation by design). Zero T013 false positives on the corpus
  - [x] Sandbox-escape payloads (Llama Drama, `self.__init__.__globals__`, `lipsum.__globals__`, …) reach nothing; resource-exhaustion templates stop at the limits
  - [x] Byte-for-byte fidelity vs real jinja2 3.1.6 with Hugging Face's settings: all 76 official templates identical, and 346/346 of the corpus templates jinja2 can render (top 1,000 GGUF repos). Running it found and fixed 4 renderer bugs: `_`-prefixed variables were treated as undefined, `dict(mapping, **kw)` ignored the mapping, jinja2's dropped trailing newline, and per-iteration `set` scope in loops. CI runs the official set on every push; the weekly workflow runs the corpus comparison and fails on any difference
  - [x] Go text/template renderer for Ollama templates (fields, variables, `:=`/`=`, pipelines, if/else if/range/with/break/continue, eq/ne/lt/le/gt/ge/and/or/not/len/index/slice/print/printf/json/currentDate). Renders Ollama's own Qwen3, Llama 3.2, Mistral and Gemma 3 templates. `explain ollama:<model>` (local store, else registry) and `.tmpl` files; T013 rendered evidence now also covers Ollama template layers in `local`, `repo ollama:` and `watch`
  - [x] Probes also try the phrase as the whole user message, for exact comparisons (`eq .Content "..."`, `== '...'`). Corpus still at zero T013 false positives
- [x] F-03 Optional prompt-injection classifier (T015): protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0) via ONNX Runtime 1.31 + SentencePiece (Microsoft.ML.Tokenizers 2.0.1). `modelcheck classifier download` (sha256-verified) / `classifier test "text"`, `--classifier` on any scan. Tokenizer verified against the model's tokenizer.json. Scores only text that differs from the nearest official template, trigger-probe additions, and system prompts (never `raise_exception` messages). Measured: on its own it flags ordinary instructions in 13% of corpus templates, so T015 is Info unless a trigger (T005/T013) or an injected-looking copy (T010) corroborates it; corpus stays at 6.5%. The exe runs without onnxruntime; with `--classifier` a missing/mismatched library gives a clear error. Releases ship the library next to the exe
- [~] F-04 Integrations
  - [x] Ollama pre-pull check: `repo ollama:<model>[:tag]` / `ollama:user/model` reads the registry manifest, template and system layers, and the GGUF header via Range (8 MiB of a 1.2 GiB model). `ollama:hf.co/...` routes to the Hugging Face check
  - [x] `scripts/ollama-safe-pull.{sh,ps1}` and `scripts/lms-safe-get.{sh,ps1}`: run `modelcheck repo` first and refuse to download on high/critical findings unless `--force`/`-Force` (`--check-only` to just check). Verified: blocks an abliterated repo with a run-this-script card (exit 2)
  - [x] Open WebUI filter (`integrations/open-webui/modelcheck_filter.py`): fetches each Ollama model's template and system prompt via `/api/show`, scans them with the modelcheck binary, blocks chats at `block_at` (default High), caches per model, optional fail-closed. Tested against a fake Ollama and the real binary (clean allowed, poisoned blocked, cache reused); CI runs that test. Not tested inside a real Open WebUI instance
  - [ ] LM Studio plugin (TypeScript SDK). The `lms-safe-get` wrapper covers downloads for now
- [x] F-05 Other formats
  - [x] safetensors: F001–F006 (header length, JSON, dtypes, offsets vs shape, overlaps, unused bytes with executable search, `__metadata__` payload checks)
  - [x] Pickle: PK001–PK004, opcode walker for protocols 0–5 (GLOBAL, STACK_GLOBAL with memo), PyTorch zip and legacy multi-pickle torch files; never executes. Verified against real Python pickles of every protocol
  - [x] `scan` handles folders of mixed formats and Hugging Face `tokenizer_config.json` / `chat_template.jinja`
  - [x] `repo` checks up to 3 pickle and 2 safetensors files remotely (1 MiB of GPT-2's 523 MiB `pytorch_model.bin`)
  - [x] ONNX: OX001–OX005. Protobuf walk (incl. subgraphs and sparse initializers) without loading weights: external-data locations that are absolute or contain `..` (CVE-2022-25882, CVE-2024-27318), symlinks resolving outside the model folder (CVE-2026-27489, CVE-2026-34447), custom operator domains, metadata payloads. `scan` handles .onnx; `repo` reads the 2 smallest .onnx files remotely (verified on Xenova/all-MiniLM-L6-v2). `onnx`/`onnxruntime` versions added to `audit` with CVE-2024-27318 and CVE-2026-27489
- [x] F-06 Docs: `docs/rules.md` (every rule ID), `docs/hardening.md` (five-layer guide). A docs site is not needed yet

## Sources to verify against (not the video transcript)

- Checkmarx — "Llama Drama", CVE-2024-34359 (llama-cpp-python SSTI)
- Databricks — GGML/GGUF heap overflow advisories (2024)
- Pillar Security — poisoned GGUF chat templates
- Cyera — "Bleeding Llama" (Ollama tensor size trust)
- Wiz — Ollama path traversal (2024)
- SentinelOne / Censys — exposed Ollama servers study (Jan 2026)
- ProjectDiscovery — tool-calling backdoor fine-tune
- Anthropic — Sleeper Agents (2024); Anthropic + UK AISI — 250-document poisoning
- HiddenLayer — fake "Privacy Filter" repo
