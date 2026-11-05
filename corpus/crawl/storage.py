"""Content-addressed payload paths and migration of the former document-based layout."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any

from .rarity import Catalog
from .settings import CrawlSettings


def payload_path(settings: CrawlSettings, sha256: str, kind: str) -> Path:
    if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
        raise ValueError("Payload SHA-256 must be 64 lowercase hexadecimal characters")
    if kind not in ("deflate", "png"):
        raise ValueError(f"Unsupported payload kind: {kind}")
    return settings.corpus_dir / kind / sha256[:2] / f"{sha256}.{kind}"


def source_path(settings: CrawlSettings, sha256: str) -> Path:
    # Validate document hashes with the same invariant as payload hashes.
    payload_path(settings, sha256, "deflate")
    return settings.sources_dir / sha256[:2] / f"{sha256}.json"


def file_hash(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def copy_verified(source: Path, target: Path, sha256: str) -> None:
    if file_hash(source) != sha256:
        raise ValueError(f"Source checksum mismatch: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        shutil.copyfile(source, target)
    if file_hash(target) != sha256:
        raise ValueError(f"Destination checksum mismatch: {target}")


def migrate_storage(settings: CrawlSettings) -> dict[str, int]:
    """Copy and verify payloads, commit all new references, then remove only verified old files.

    Do not run a crawler concurrently. An immediate transaction keeps the catalog unchanged while
    the filesystem migration is prepared; failures leave the original payloads in place.
    """
    cleanup: dict[Path, str] = {}
    result = {"payloads": 0, "sources": 0, "legacy_documents": 0, "removed_files": 0, "retained_empty_directories": 0}
    with Catalog(settings.catalog_path) as catalog:
        db = catalog.connection
        with db:
            db.execute("BEGIN IMMEDIATE")
            streams = db.execute("SELECT * FROM saved_streams ORDER BY id").fetchall()
            per_record: dict[int, dict[int, Path]] = {}
            copied: set[Path] = set()
            moved: set[Path] = set()
            for stream in streams:
                old = Path(stream["path"])
                target = payload_path(settings, stream["sha256"], stream["extract"])
                if old != target and not old.is_relative_to(settings.corpus_dir):
                    raise ValueError(f"Old payload is outside corpus directory: {old}")
                if target not in copied:
                    copy_verified(old, target, stream["sha256"])
                    copied.add(target)
                elif old not in cleanup and file_hash(old) != stream["sha256"]:
                    raise ValueError(f"Source checksum mismatch: {old}")
                if old != target:
                    cleanup[old] = stream["sha256"]
                    moved.add(target)
                per_record.setdefault(stream["record_id"], {})[stream["stream_index"]] = target
                db.execute("UPDATE saved_streams SET path=? WHERE id=?", (str(target), stream["id"]))
            records = db.execute("SELECT id,sha256,saved_path FROM records WHERE saved_path IS NOT NULL").fetchall()
            for record in records:
                old = Path(record["saved_path"])
                target = source_path(settings, record["sha256"])
                if old == target:
                    continue
                if not old.is_relative_to(settings.corpus_dir):
                    if old.is_relative_to(settings.legacy_dir):
                        continue
                    raise ValueError(f"Old record save is outside corpus directory: {old}")
                if old.is_dir():
                    metadata = old / "source.json"
                    document: dict[str, Any] = json.loads(metadata.read_text(encoding="utf-8"))
                    for entry in document["saved"]:
                        entry["file"] = os.path.relpath(per_record[record["id"]][entry["index"]], target.parent)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.exists() and json.loads(target.read_text(encoding="utf-8")) != document:
                        raise ValueError(f"Conflicting source metadata: {target}")
                    target.write_text(json.dumps(document, indent=2), encoding="utf-8")
                    cleanup[metadata] = file_hash(metadata)
                    result["sources"] += 1
                else:
                    target = settings.legacy_dir / f"{record['sha256']}{old.suffix}"
                    copy_verified(old, target, record["sha256"])
                    cleanup[old] = record["sha256"]
                    sidecar = old.with_name(old.name + ".json")
                    if sidecar.exists():
                        sha = file_hash(sidecar)
                        copy_verified(sidecar, target.with_name(target.name + ".json"), sha)
                        cleanup[sidecar] = sha
                    result["legacy_documents"] += 1
                db.execute("UPDATE records SET saved_path=? WHERE id=?", (str(target), record["id"]))
            result["payloads"] = len(moved)
        for old, sha in cleanup.items():
            if file_hash(old) != sha:
                raise ValueError(f"Old file changed before cleanup; retained: {old}")
            old.unlink()
            result["removed_files"] += 1
        parents: list[Path] = []
        for name in ("rare_family", "rare_variant", "rare_exact", "rare_failure", "poor_model", "sampled"):
            root = settings.corpus_dir / name
            if root.is_dir():
                parents.extend(p for p in root.rglob("*") if p.is_dir())
                parents.append(root)
        for parent in sorted(parents, key=lambda p: len(p.parts), reverse=True):
            if not list(parent.iterdir()):
                try:
                    parent.rmdir()
                except PermissionError as error:
                    if getattr(error, "winerror", None) != 32:
                        raise
                    result["retained_empty_directories"] += 1
                    logging.getLogger(__name__).warning("Windows has locked an empty legacy directory; retained: %s", parent)
    return result
