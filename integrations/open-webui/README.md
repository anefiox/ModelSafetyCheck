# Open WebUI filter

`modelcheck_filter.py` is an Open WebUI [Filter function](https://docs.openwebui.com/features/plugin/functions/filter).
Before a chat reaches an Ollama model, it fetches the model's chat template and system prompt from Ollama
(`/api/show`), scans them with `modelcheck`, and blocks the chat when a finding reaches `block_at` (High by default).
Verdicts are cached per model for `cache_minutes`, so a template rewritten through Ollama's API is picked up again.

1. Make the `modelcheck` binary available where Open WebUI runs. With Docker, mount the Linux binary from a release,
   e.g. `-v /opt/modelcheck/modelcheck:/usr/local/bin/modelcheck:ro`.
2. Admin Panel → Functions → **+** → paste `modelcheck_filter.py` → Save, then enable it (globally or per model).
3. Set the valves: `modelcheck_path`, `ollama_base_url` (inside Docker usually `http://host.docker.internal:11434`),
   `block_at`, and `fail_closed` if a failed check should block the chat.

`test_modelcheck_filter.py` runs the filter against a fake Ollama and the real binary:

```bash
MODELCHECK=path/to/modelcheck python integrations/open-webui/test_modelcheck_filter.py
```
