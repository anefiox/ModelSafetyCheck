"""Renders every template in data/known-templates.json with real jinja2, configured like Hugging Face's
apply_chat_template, using the same sample conversation as modelcheck's TemplateExplainer.
RenderFidelityTests compares modelcheck's sandboxed renderer against this output byte for byte.

    pip install jinja2
    python tools/render-fidelity/render_reference.py > reference.json
    MODELCHECK_FIDELITY_FILE=reference.json dotnet test --filter RenderFidelityTests
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from jinja2.ext import Extension, loopcontrols
from jinja2.sandbox import ImmutableSandboxedEnvironment
from jinja2 import nodes

NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


class GenerationTag(Extension):
    """Hugging Face's {% generation %} block: renders its body."""
    tags = {"generation"}

    def parse(self, parser):
        lineno = next(parser.stream).lineno
        body = parser.parse_statements(["name:endgeneration"], drop_needle=True)
        return nodes.Scope(body, lineno=lineno)


def raise_exception(message):
    raise ValueError(message)


def tojson(x, ensure_ascii=False, indent=None, separators=None, sort_keys=False):
    return json.dumps(x, ensure_ascii=ensure_ascii, indent=indent, separators=separators, sort_keys=sort_keys)


def conversation(with_system):
    messages = [{"role": "system", "content": "You are a helpful assistant."}] if with_system else []
    return messages + [
        {"role": "user", "content": "What is the capital of France?"},
        {"role": "assistant", "content": "The capital of France is Paris."},
        {"role": "user", "content": "Hello there."},
    ]


def render(template):
    env = ImmutableSandboxedEnvironment(trim_blocks=True, lstrip_blocks=True, extensions=[GenerationTag, loopcontrols])
    env.filters["tojson"] = tojson
    env.globals["raise_exception"] = raise_exception
    env.globals["strftime_now"] = lambda fmt: NOW.strftime(fmt)
    compiled = env.from_string(template)
    for with_system in (True, False):
        try:
            return compiled.render(messages=conversation(with_system), add_generation_prompt=True, bos_token="<s>", eos_token="</s>")
        except ValueError:
            continue
    return None


def main():
    # Default: the official templates. With a path argument: a {"key": "template"} file (e.g. from TemplateCorpus --dump).
    if len(sys.argv) > 1:
        items = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).items()
    else:
        root = Path(__file__).resolve().parents[2]
        data = json.loads((root / "data" / "known-templates.json").read_text(encoding="utf-8"))
        items = [(t["source"] + ("#" + t["name"] if t.get("name") else "") + ("@" + t["revision"][:10] if t.get("revision") else ""), t["text"])
                 for t in data["templates"]]
    out = {}
    for key, text in items:
        try:
            out[key] = render(text)
        except Exception as ex:  # a template jinja2 itself cannot render is skipped by the test
            out[key] = None
            print(f"{key}: {ex}", file=sys.stderr)
    sys.stdout.reconfigure(encoding="utf-8")
    json.dump(out, sys.stdout, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
