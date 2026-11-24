"""Stream current scanner JSON reports, validating completion and measured totals."""

from collections.abc import Generator, Iterator
from pathlib import Path
from typing import Any

import ijson
from ijson.common import ObjectBuilder


def _value(events: Iterator[tuple[str, Any]], event: str, value: Any) -> Any:
    builder = ObjectBuilder()
    builder.event(event, value)
    depth = int(event in ("start_map", "start_array"))
    while depth:
        event, value = next(events)
        builder.event(event, value)
        depth += int(event in ("start_map", "start_array")) - int(event in ("end_map", "end_array"))
    return builder.value


def json_scan_records(path: str | Path) -> Generator[tuple[str, dict[str, Any]], None, None]:
    totals = dict.fromkeys(("entries", "successful_streams", "verified_streams", "successful_deflate_bytes",
                           "successful_plaintext_bytes", "successful_correction_bytes"), 0)
    with Path(path).open("rb") as source:
        events = iter(ijson.basic_parse(source, use_float=True))
        try:
            if next(events) != ("start_map", None):
                raise ValueError("Scanner JSON must be an object")
            header: dict[str, Any] = {}
            seen: set[str] = set()
            files_seen = False
            summary: dict[str, Any] | None = None
            while True:
                event, key = next(events)
                if event == "end_map":
                    break
                if event != "map_key" or key in seen:
                    raise ValueError("Invalid or duplicate scanner JSON field")
                seen.add(key)
                event, value = next(events)
                if key == "files":
                    if (type(header.get("schema_version")) is not int or header["schema_version"] != 1
                            or not isinstance(header.get("configuration"), dict)):
                        raise ValueError("Unsupported or missing scanner JSON header")
                    if event != "start_array" or summary is not None:
                        raise ValueError("Invalid scanner files array")
                    files_seen = True
                    yield "header", header
                    while True:
                        event, value = next(events)
                        if event == "end_array":
                            break
                        if event != "start_map":
                            raise ValueError("Scanner file must be an object")
                        record = _value(events, event, value)
                        totals["entries"] += 1
                        for stream in record["streams"]:
                            if stream["status"] == "ok":
                                totals["successful_streams"] += 1
                                totals["verified_streams"] += stream["verified"]
                                totals["successful_deflate_bytes"] += stream["deflate_bytes"]
                                totals["successful_plaintext_bytes"] += stream["plaintext_bytes"]
                                totals["successful_correction_bytes"] += stream["correction_bytes"]
                        yield "file", record
                elif key == "summary":
                    if not files_seen or event != "start_map":
                        raise ValueError("Scanner summary must follow files")
                    decoded = _value(events, event, value)
                    if not isinstance(decoded, dict):
                        raise ValueError("Scanner summary must be an object")
                    summary = decoded
                    if any(summary.get(name) != total for name, total in totals.items()):
                        raise ValueError("Scanner JSON totals do not reconcile")
                else:
                    if files_seen:
                        raise ValueError("Unexpected scanner field after files")
                    header[key] = _value(events, event, value)
            if not files_seen or summary is None:
                raise ValueError("Incomplete scanner JSON report")
            if next(events, None) is not None:
                raise ValueError("Trailing scanner JSON data")
            yield "summary", summary
        except StopIteration as error:
            raise ValueError("Incomplete scanner JSON report") from error
