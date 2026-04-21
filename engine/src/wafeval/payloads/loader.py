"""Payload YAML loader.

Schema: see ``docs/ADDING_PAYLOADS.md`` and ``wafeval.models.Payload``.
Destructive patterns are rejected at validation time (prompt.md §13).
"""
from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import TypeAdapter

from wafeval.models import Payload, VulnClass

_CORPUS_DIR = Path(__file__).parent
_PAYLOAD_LIST = TypeAdapter(list[Payload])


def load_yaml_file(path: Path) -> list[Payload]:
    """Load and validate a single YAML corpus file."""
    raw = yaml.safe_load(path.read_text())
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: top-level YAML must be a list of payload entries")
    return _PAYLOAD_LIST.validate_python(raw)


def load_corpus(
    classes: list[VulnClass] | None = None,
    corpus_dir: Path | None = None,
) -> list[Payload]:
    """Load every ``<class>.yaml`` under the corpus directory.

    If ``classes`` is given, only those files are read (missing files are an
    error — you asked for sqli and there is no sqli.yaml).
    """
    root = corpus_dir or _CORPUS_DIR
    targets = classes or list(VulnClass)
    all_payloads: list[Payload] = []
    for cls in targets:
        f = root / f"{cls.value}.yaml"
        if not f.exists():
            if classes is not None:
                raise FileNotFoundError(f"corpus file missing: {f}")
            continue
        all_payloads.extend(load_yaml_file(f))
    return all_payloads
