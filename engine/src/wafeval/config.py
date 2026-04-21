"""Target endpoint + route map loader.

Parses ``targets.yaml`` (shipped with the package) into typed config objects
the runner can consume. Keeps the YAML path a single source of truth so the
engine and docs don't drift.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict

from wafeval.models import VulnClass


class DvwaLogin(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: Literal["POST"]
    path: str
    form_tokenized: bool
    username: str
    password: str


class EndpointSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: Literal["GET", "POST"]
    path: str
    query: dict[str, str] = {}
    form: dict[str, str] = {}
    expect_auth: bool = False
    notes: str | None = None


class TargetSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_path: str = ""
    login: DvwaLogin | None = None
    endpoints: dict[VulnClass, EndpointSpec]


class Route(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str
    waf: str
    target: str


class TargetsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    targets: dict[str, TargetSpec]
    routes: list[Route]

    def endpoint_for(self, target: str, vuln_class: VulnClass) -> EndpointSpec | None:
        spec = self.targets.get(target)
        if spec is None:
            return None
        return spec.endpoints.get(vuln_class)


_DEFAULT = Path(__file__).with_name("targets.yaml")


def load_targets(path: Path | None = None) -> TargetsConfig:
    data = yaml.safe_load((path or _DEFAULT).read_text())
    return TargetsConfig.model_validate(data)
