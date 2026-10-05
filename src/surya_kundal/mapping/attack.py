"""The MITRE ATT&CK technique catalog, vendored so mapping works offline.

MITRE ATT&CK(R) is a registered trademark of The MITRE Corporation. The technique
names and tactics in ``data/attack_enterprise.json`` come from the Enterprise ATT&CK
dataset published at https://github.com/mitre-attack/attack-stix-data and are used
under MITRE's terms: (c) The MITRE Corporation. Reproduced and distributed with the
permission of The MITRE Corporation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    is_subtechnique: bool

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"


@dataclass(frozen=True)
class Catalog:
    version: str
    techniques: dict[str, Technique]

    def get(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id)

    def __contains__(self, technique_id: str) -> bool:
        return technique_id in self.techniques


@lru_cache(maxsize=1)
def load_catalog() -> Catalog:
    raw = (
        resources.files("surya_kundal.mapping")
        .joinpath("data/attack_enterprise.json")
        .read_text(encoding="utf-8")
    )
    data = json.loads(raw)
    techniques = {
        tid: Technique(tid, t["name"], tuple(t["tactics"]), bool(t["sub"]))
        for tid, t in data["techniques"].items()
    }
    return Catalog(version=str(data["attack_version"]), techniques=techniques)
