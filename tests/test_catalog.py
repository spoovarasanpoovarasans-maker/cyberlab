from pathlib import Path

import pytest

from app.catalog import load_catalog

from .helpers import PROJECT_ROOT


def test_real_catalog_loads():
    catalog = load_catalog(PROJECT_ROOT / "challenges")
    assert set(catalog) == {"sqli-login", "xss-guestbook", "cmdi-ping"}
    for challenge in catalog.values():
        assert challenge.image.startswith("cyberlab/challenge-")
        assert challenge.container_port == 8000
        assert challenge.difficulty in {"easy", "medium", "hard", "insane"}
        assert challenge.hints


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_rejects_non_cyberlab_image(tmp_path):
    _write(
        tmp_path / "bad" / "challenge.yaml",
        """
id: bad
title: Bad
difficulty: easy
image: evil/image:latest
container_port: 8000
""",
    )
    with pytest.raises(ValueError, match="cyberlab/challenge-"):
        load_catalog(tmp_path)


def test_rejects_id_directory_mismatch(tmp_path):
    _write(
        tmp_path / "dir" / "challenge.yaml",
        """
id: other
title: Other
difficulty: easy
image: cyberlab/challenge-other:latest
container_port: 8000
""",
    )
    with pytest.raises(ValueError, match="must match directory"):
        load_catalog(tmp_path)


def test_rejects_empty_catalog(tmp_path):
    with pytest.raises(ValueError, match="no challenges found"):
        load_catalog(tmp_path)
