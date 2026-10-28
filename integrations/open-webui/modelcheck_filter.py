"""
title: ModelSafetyCheck
description: Before a chat is sent to an Ollama model, checks the model's chat template and system prompt with modelcheck and blocks the chat when it finds high-risk content (hidden instructions, trigger phrases, sandbox escapes).
author: ModelSafetyCheck contributors
version: 0.1.0
license: MIT
"""

# Install: Open WebUI → Admin Panel → Functions → + → paste this file, save, enable it, and enable it for your models
# (or make it global). The `modelcheck` binary must be available where Open WebUI runs; in Docker, mount the
# Linux binary from a release and set the `modelcheck_path` valve.

import asyncio
import json
import os
import tempfile
import time
import urllib.request
from typing import Any, Awaitable, Callable, Optional

from pydantic import BaseModel, Field

SEVERITIES = ["Info", "Low", "Medium", "High", "Critical"]


class Filter:
    class Valves(BaseModel):
        modelcheck_path: str = Field(default="modelcheck", description="Path to the modelcheck executable.")
        ollama_base_url: str = Field(default="http://localhost:11434", description="Ollama API that serves the models.")
        block_at: str = Field(default="High", description="Block chats at this severity or above: Medium, High or Critical.")
        cache_minutes: int = Field(default=60, description="Re-check a model after this many minutes (templates can be rewritten through the API).")
        fail_closed: bool = Field(default=False, description="Block the chat when the check itself fails (modelcheck missing, Ollama unreachable).")

    def __init__(self):
        self.valves = self.Valves()
        self._cache: dict[str, tuple[float, dict]] = {}

    async def inlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None,
    ) -> dict:
        model = body.get("model", "")
        if not model:
            return body

        verdict = self._cached(model)
        if verdict is None:
            await self._status(__event_emitter__, f"modelcheck: checking {model}…", done=False)
            try:
                verdict = await asyncio.to_thread(self.check_model, model)
            except Exception as ex:  # the check failed, not the model
                verdict = {"error": str(ex)}
            self._cache[model] = (time.time(), verdict)

        if "error" in verdict:
            await self._status(__event_emitter__, f"modelcheck could not check {model}: {verdict['error']}", done=True)
            if self.valves.fail_closed:
                raise Exception(f"ModelSafetyCheck could not check {model}: {verdict['error']}")
            return body

        if blocks(verdict, self.valves.block_at):
            raise Exception(f"ModelSafetyCheck blocked this chat with {model}: {summary(verdict)}. Run `modelcheck explain ollama:{model}` for details.")

        await self._status(__event_emitter__, f"modelcheck: {model}: {summary(verdict) or 'no findings'}", done=True)
        return body

    def _cached(self, model: str) -> Optional[dict]:
        hit = self._cache.get(model)
        if hit and time.time() - hit[0] < self.valves.cache_minutes * 60:
            return hit[1]
        return None

    @staticmethod
    async def _status(emitter, description: str, done: bool) -> None:
        if emitter:
            await emitter({"type": "status", "data": {"description": description, "done": done}})

    def check_model(self, model: str) -> dict:
        """Fetches the template and system prompt Ollama will use, and scans them with modelcheck."""
        show = fetch_show(self.valves.ollama_base_url, model)
        findings: list[dict] = []
        with tempfile.TemporaryDirectory(prefix="modelcheck-") as tmp:
            files = []
            if show.get("template"):
                files.append(write(tmp, "template.tmpl", show["template"]))
            if show.get("system"):
                # A system prompt is plain text; scanning it as a Go template with no actions applies the text rules.
                files.append(write(tmp, "system.tmpl", show["system"]))
            if not files:
                return {"findings": []}
            reports = run_modelcheck(self.valves.modelcheck_path, files)
        for report in reports:
            if report.get("error"):
                raise RuntimeError(report["error"])
            findings.extend(report.get("findings", []))
        return {"findings": findings}


def fetch_show(base_url: str, model: str) -> dict:
    request = urllib.request.Request(
        base_url.rstrip("/") + "/api/show",
        data=json.dumps({"model": model}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read())


def write(directory: str, name: str, text: str) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def run_modelcheck(executable: str, files: list[str]) -> list[dict]:
    import subprocess

    # Exit codes 0-2 are results (clean / warnings / high); 3 is a scan error.
    result = subprocess.run([executable, "scan", *files, "--format", "json"], capture_output=True, text=True, timeout=120)
    if result.returncode == 3 or not result.stdout.strip():
        raise RuntimeError(result.stderr.strip() or f"modelcheck exited with {result.returncode}")
    return json.loads(result.stdout)


def blocks(verdict: dict, block_at: str) -> bool:
    threshold = SEVERITIES.index(block_at) if block_at in SEVERITIES else SEVERITIES.index("High")
    return any(SEVERITIES.index(f.get("severity", "Info")) >= threshold for f in verdict.get("findings", []))


def summary(verdict: dict) -> str:
    serious = [f for f in verdict.get("findings", []) if SEVERITIES.index(f.get("severity", "Info")) >= SEVERITIES.index("Medium")]
    return "; ".join(f"{f['ruleId']} {f['severity']}: {f['title']}" for f in serious[:3])
