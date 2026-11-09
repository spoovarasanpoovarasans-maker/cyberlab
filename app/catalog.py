"""Load and validate challenge definitions from challenges/*/challenge.yaml."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

DIFFICULTIES = {"easy", "medium", "hard", "insane"}


@dataclass(frozen=True)
class Challenge:
    id: str
    title: str
    category: str
    difficulty: str
    description: str
    image: str
    container_port: int
    ttl_minutes: int
    points: int
    hints: tuple[str, ...] = ()
    solution: str = ""
    order: int = 100


def _require(data: dict, key: str, path: Path):
    if key not in data or data[key] in (None, ""):
        raise ValueError(f"{path}: missing required field '{key}'")
    return data[key]


def load_catalog(root: Path) -> dict[str, Challenge]:
    root = Path(root)
    if not root.is_dir():
        raise ValueError(f"challenge catalog directory not found: {root}")

    catalog: dict[str, Challenge] = {}
    for path in sorted(root.glob("*/challenge.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: challenge.yaml must be a mapping")

        challenge_id = str(_require(raw, "id", path)).strip()
        if challenge_id != path.parent.name:
            raise ValueError(
                f"{path}: id '{challenge_id}' must match directory '{path.parent.name}'"
            )
        if challenge_id in catalog:
            raise ValueError(f"{path}: duplicate challenge id '{challenge_id}'")

        difficulty = str(_require(raw, "difficulty", path)).lower()
        if difficulty not in DIFFICULTIES:
            raise ValueError(f"{path}: difficulty must be one of {sorted(DIFFICULTIES)}")

        image = str(_require(raw, "image", path))
        if not image.startswith("cyberlab/challenge-"):
            raise ValueError(
                f"{path}: image must start with 'cyberlab/challenge-' (got {image!r})"
            )

        port = int(_require(raw, "container_port", path))
        if not 1 <= port <= 65535:
            raise ValueError(f"{path}: container_port out of range")

        hints = raw.get("hints") or []
        if not isinstance(hints, list):
            raise ValueError(f"{path}: hints must be a list")

        catalog[challenge_id] = Challenge(
            id=challenge_id,
            title=str(_require(raw, "title", path)),
            category=str(raw.get("category", "web")),
            difficulty=difficulty,
            description=str(raw.get("description", "")),
            image=image,
            container_port=port,
            ttl_minutes=max(1, int(raw.get("ttl_minutes", 30))),
            points=max(0, int(raw.get("points", 100))),
            hints=tuple(str(hint) for hint in hints),
            solution=str(raw.get("solution", "")),
            order=int(raw.get("order", 100)),
        )

    if not catalog:
        raise ValueError(f"no challenges found under {root}")

    return dict(sorted(catalog.items(), key=lambda item: (item[1].order, item[1].title)))
