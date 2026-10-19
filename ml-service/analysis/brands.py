from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).parent / "data" / "brands.json"


@dataclass(frozen=True)
class Brand:
    name: str
    labels: tuple
    domains: frozenset
    sector: str


@lru_cache(maxsize=1)
def load_brands(path: str | None = None) -> tuple[Brand, ...]:
    raw = json.loads(Path(path or DATA).read_text())["brands"]
    return tuple(Brand(b["name"], tuple(b["labels"]), frozenset(b["domains"]), b["sector"]) for b in raw)


def official_brand(registered_domain: str, brands=None) -> Brand | None:
    """The brand that officially owns this registered domain, if any."""
    for b in brands or load_brands():
        if registered_domain in b.domains:
            return b
    return None
