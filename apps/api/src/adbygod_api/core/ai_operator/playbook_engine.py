from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class EngineStep:
    id: str
    technique: str
    params: dict = field(default_factory=dict)
    on_success: str = "done"
    on_failure: str = "done"
    auto_chain: bool = False


class PlaybookEngine:
    def __init__(self, base_dir: str | None = None):
        self._base = Path(base_dir or os.path.expanduser("~/.adbygod/playbooks"))
        self._base.mkdir(parents=True, exist_ok=True)

    def parse(self, yaml_text: str) -> dict:
        data = yaml.safe_load(yaml_text)
        return {
            "name": data.get("name", "Unnamed"),
            "description": data.get("description", ""),
            "steps": data.get("steps", []),
        }

    def resolve_params(self, step: EngineStep, context: dict) -> dict:
        """Replace {{ variable }} placeholders in params with context values."""
        resolved = {}
        for k, v in step.params.items():
            if isinstance(v, str):
                v = re.sub(
                    r"\{\{\s*(\w+)\s*\}\}",
                    lambda m: str(context.get(m.group(1), "{{ " + m.group(1) + " }}")),
                    v,
                )
            resolved[k] = v
        return resolved

    def list_playbooks(self) -> list[dict]:
        out = []
        for f in sorted(self._base.glob("*.yaml")):
            try:
                data = yaml.safe_load(f.read_text())
                out.append({
                    "filename": f.name,
                    "name": data.get("name", f.stem),
                    "description": data.get("description", ""),
                    "step_count": len(data.get("steps", [])),
                })
            except Exception:
                pass
        return out

    def load(self, filename: str) -> dict:
        path = self._base / filename
        if not path.exists():
            raise FileNotFoundError(f"Playbook not found: {filename}")
        return self.parse(path.read_text())

    def get_step(self, playbook: dict, step_id: str) -> dict | None:
        return next((s for s in playbook.get("steps", []) if s.get("id") == step_id), None)
