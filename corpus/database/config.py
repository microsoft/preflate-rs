"""Read machine-local database discovery and query settings."""

import tomllib
from pathlib import Path
from typing import Any


def load_local_config(path: str | Path) -> dict[str, Any]:
    source = Path(path).resolve()
    with source.open("rb") as stream:
        config = tomllib.load(stream)
    for section in ("database", "scope", "queries", "locations"):
        if section in config and not isinstance(config[section], dict):
            raise ValueError(f"Local config [{section}] must be a table")
        config.setdefault(section, {})
    database = config["database"]
    if not isinstance(database.get("path"), str) or not database["path"].strip():
        raise ValueError("Local config requires database.path")
    if database.get("foreign_keys", True) is not True:
        raise ValueError("Foreign keys must remain enabled")
    for section, name in (("database", "path"), ("locations", "scanner")):
        value = config[section].get(name)
        if value is not None:
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Local config {section}.{name} must be a nonempty path")
            config[section][name] = str((source.parent / value).resolve())
    scope = config["scope"]
    if "report" in scope:
        raise ValueError("scope.report is no longer supported; configure scope.runs directly")
    runs = scope.get("runs", [])
    if not isinstance(runs, list) or any(not isinstance(run, str) or not run.strip() for run in runs) or len(set(runs)) != len(runs):
        raise ValueError("Local scope must contain distinct nonempty run labels")
    scope["runs"] = runs
    for section, name, minimum in (
        ("queries", "limit", 1), ("queries", "min_deflate_bytes", 0),
    ):
        value = config[section].get(name)
        if value is not None and (type(value) is not int or value < minimum):
            raise ValueError(f"Local config {section}.{name} must be an integer >= {minimum}")
    return config
