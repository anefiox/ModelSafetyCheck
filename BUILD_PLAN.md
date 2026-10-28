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

Status: `[ ]` todo · `[~]` in progress · `[x]` done. Every rule has a stable ID.

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
- [ ] T010 Known-good / unknown template (see D-02) — phase 2
- [ ] T012 Special-token injection: template emits role markers taken from user content unescaped — phase 2

Tokenizer rules (GGUF-K)
- [x] K001 BOS/EOS/PAD/UNK ids out of vocabulary range
- [x] K002 Vocab size ≠ embedding tensor dimension
- [ ] K003 Special/added tokens whose text looks like instructions or role spoofing — phase 2

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
- [ ] L-06 llama.cpp cache (`LLAMA_CACHE`, `~/.cache/llama.cpp`) — phase 2
- [ ] L-07 Hugging Face hub cache (`~/.cache/huggingface/hub`) `.gguf` files — phase 2
- [ ] L-08 LM Studio per-model prompt-template overrides (user config under `~/.lmstudio/.internal/`) — these replace the embedded template the same way Ollama's layer does — phase 2
- [ ] L-10 Ollama Modelfile `RENDERER`/`PARSER` built-in templates (newer Ollama) — note when the template isn't on disk — phase 2

CLI / output
- [x] C-01 `modelcheck scan <path...>` (files or directories, recursive)
- [x] C-02 `modelcheck local`
- [x] C-03 Text output with severity colours
- [x] C-04 `--format json`
- [x] C-05 `--dump-template` prints extracted templates
- [x] C-06 Exit codes 0/1/2/3
- [x] C-07 `--min-severity` filter
- [ ] C-08 `--format sarif` — phase 2
- [x] C-09 Native AOT publish verified on win-x64 (4.8 MB single exe, no trim/AOT warnings). On Windows the link step needs the VS C++ build tools and `vswhere.exe` on PATH (`C:\Program Files (x86)\Microsoft Visual Studio\Installer`)

Testing
- [x] X-01 `GgufWriter` test helper that can write valid and deliberately malformed files
- [x] X-02 One fixture per structural rule
- [x] X-03 Malicious template fixtures (SSTI, trigger, hidden instruction, unicode tags)
- [x] X-04 Clean template fixtures from real model families (no false positives) — ChatML/Qwen, Llama 3, Mistral, Gemma, SmolLM3 mode switches, Ollama Go template; also verified clean on a real Gemma 4 12B GGUF
- [ ] X-06 Corpus test: run over the embedded templates of the top ~500 GGUF repos and track the false-positive rate (needs `repo`) — phase 3
- [ ] X-07 Tests on Linux and macOS in CI (path handling, Ollama system install locations) — phase 2
- [ ] X-05 SharpFuzz harness for the parser — phase 2

### Phase 2 — `audit`, reference data, releases

Reference data
- [ ] D-01 `known-templates.json`: SHA-256 of official templates (Llama 3.x, Qwen 2.5/3, Mistral, Gemma 2/3/4, Phi, DeepSeek, GPT-OSS, …) with source URL
- [ ] D-02 T010 Template matches known-good (info) / unknown (warning with nearest-match diff)
- [ ] D-03 Normalised template hashing (whitespace-insensitive) to avoid noise
- [ ] D-04 Tool to regenerate the DB from upstream repos (`tools/build-template-db`)
- [ ] D-05 `runner-vulns.json` from real advisories (Bleeding Llama, Ollama Windows updater signature bypass, Ollama path traversal 2024, Ollama DNS rebinding 2024, Ollama desktop drive-by 2025, llama-cpp-python CVE-2024-34359, SGLang template SSTI 2026). Verify every version range against the advisory, not the video.

`audit` command
- [ ] A-01 Detect installed runners + versions (Ollama, LM Studio, llama.cpp server, vLLM, SGLang)
- [ ] A-02 Match versions against `runner-vulns.json`
- [ ] A-03 `OLLAMA_HOST` in process env, user/system env (Windows registry), systemd unit + overrides, launchd plist
- [ ] A-04 Listening sockets on known ports (11434, 1234, 8080, 8000, 30000): flag non-loopback binds
- [ ] A-05 Docker: containers publishing AI ports on 0.0.0.0 (note ufw bypass on Linux)
- [ ] A-06 LM Studio server settings: network serving enabled, require-auth disabled
- [ ] A-07 Live reachability probe on LAN IP (opt-in `--probe`)
- [ ] A-08 Ollama auto-update setting on Windows
- [ ] A-09 Remediation text for every finding (loopback, Tailscale, auth reverse proxy, update)

Agent risk (`audit --agent-dir <path>`)
- [ ] G-01 Secrets reachable: `.env*`, `id_rsa`/`id_ed25519`, `.aws/credentials`, `.npmrc`, `.pypirc`, `*.pem`, kube configs, git credential files, high-entropy tokens
- [ ] G-02 Overall risk rating combining: model provenance × tool access × secret exposure × network exposure
- [ ] G-03 Privilege-separation guidance (exec process ≠ network process)

Other
- [ ] K003 (see above), L-06, L-07, C-08 SARIF, X-05 fuzzing
- [ ] R-01 Native AOT publish profiles + GitHub Actions release workflow (all RIDs, checksums)
- [ ] R-02 `dotnet tool` package

### Phase 3 — `repo` + `watch`

`repo <hf-user/repo>` (pre-download)
- [ ] H-01 List repo files via HF API
- [ ] H-02 Flag lure files: `.bat`, `.cmd`, `.ps1`, `.sh`, `.exe`, `.dll`, `.dmg`, `.pkg`, `.msi`, `.py`, `.js`, `.jar`, `.lnk`, `.scr`, archives
- [ ] H-03 README analysis: instructions to run scripts / paste commands / disable AV
- [ ] H-04 Header-only GGUF scan via HTTP Range (download until header + KV parsed; cap bytes)
- [ ] H-05 Compare embedded template vs `tokenizer_config.json` / HF-displayed template (Pillar card-vs-file mismatch)
- [ ] H-06 Lineage: `general.base_model.*`, card `base_model`, merge/abliterated/uncensored markers, chain depth
- [ ] H-07 Publisher trust tier: official org / well-known quantizer allowlist (`data/trusted-publishers.json`) / unknown
- [ ] H-08 Repo age, recent creation + very high downloads, card copied from another repo (similarity) — suspicion signals
- [ ] H-09 Pickle/`.bin`/`.pt` files present → recommend picklescan / safetensors

`watch` (template drift)
- [ ] W-01 Snapshot store (`~/.modelcheck/snapshots.json`): model id → template hash, system hash, blob digest
- [ ] W-02 `watch --baseline` / `watch --check`: report changed templates/system prompts with diff
- [ ] W-03 Distinguish legit model update (blob digest changed) from template-only change (suspicious — DNS-rebinding rewrite)
- [ ] W-04 Install helpers: Windows Scheduled Task, systemd user timer, launchd agent
- [ ] W-05 Optional desktop notification

### Phase 4 — later

- [ ] F-01 GitHub Action wrapper
- [ ] F-02 Safe template evaluator (own interpreter over the Jinja AST, no host access) for `--explain`: render with sample conversations and show exactly what the model sees, with/without candidate triggers
- [ ] F-03 Optional ONNX prompt-injection classifier on extracted literals
- [ ] F-04 Integrations: Open WebUI / LM Studio plugin, pre-pull hook for Ollama
- [ ] F-05 safetensors / ONNX / other formats header checks
- [ ] F-06 Docs site: the five-layer model, hardening guide

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
