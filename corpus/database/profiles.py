"""Indexed summaries of authoritative reconstruction settings, never executable configuration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def variant(value: Any) -> tuple[str, Any]:
    if isinstance(value, str):
        return value, value
    if not isinstance(value, dict) or len(value) != 1:
        raise ValueError("Expected exactly one canonical parameter variant")
    return next(iter(value.items()))


def reconstruction_settings(report: Mapping[str, Any]) -> dict[str, Any]:
    if set(report) != {"reconstruction", "model"}:
        raise ValueError("Expected separate reconstruction settings and model hypothesis")
    reconstruction = report["reconstruction"]
    if not isinstance(reconstruction, dict):
        raise ValueError("Reconstruction settings must be an object")
    if not isinstance(report["model"], str):
        raise ValueError("Model hypothesis must be a string")
    return reconstruction


def profile_fields(report: Mapping[str, Any]) -> dict[str, Any]:
    settings = reconstruction_settings(report)
    behavior, body = variant(settings["behavior"])
    fields = {
        "block_type_strategy": settings["block_type_strategy"],
        "max_token_count": settings["max_token_count"],
    }
    if behavior == "NoDictionary":
        fields["hash_algorithm"] = "None"
        fields["strategy"] = body["strategy"]
        return fields
    if behavior not in ("Chain", "MiniZ"):
        raise ValueError(f"Unknown reconstruction behavior: {behavior}")
    common = body["common"]
    dictionary, search = common["dictionary"], common["search"]
    index, index_settings = variant(dictionary["index"])
    if index == "Chain":
        function = variant(index_settings["hash"])[0]
        hash_algorithm = {
            "Libdeflate4": "Libdeflate4Fast",
            "Libdeflate4_15": "Libdeflate4Fast15",
        }.get(function, function)
    elif index == "LibdeflateDualHash":
        hash_algorithm = "Libdeflate4"
    else:
        raise ValueError(f"Unknown dictionary index: {index}")
    distance, distance_settings = variant(common["distance"])
    bounds = distance_settings["bounds"] if distance == "Window" else None
    fields.update(
        hash_algorithm=hash_algorithm,
        add_policy=variant(dictionary["insertion"])[0],
        window_bits=dictionary["window_bits"],
        max_chain=search["budget"]["max_chain"],
        strategy=bounds if distance == "Window" else distance,
    )
    if distance == "Window":
        fields["matches_to_start_detected"] = distance_settings["history"]["matches_to_start"]
    elif distance == "Enabled":
        fields["matches_to_start_detected"] = distance_settings["matches_to_start"]
    if behavior == "MiniZ":
        fields.update(matching_type="MiniZ", max_dist_3_matches=body["short_match_cutoff"])
    else:
        parser, parser_settings = variant(body["parser"])
        fields.update(
            matching_type=parser, nice_length=search["nice_length"],
            very_far_matches_detected=bounds in ("Full", "ExcludeOldest"),
        )
        if parser == "Lazy":
            minimum, minimum_settings = variant(parser_settings["minimum"])
            if minimum == "Three":
                fields["max_dist_3_matches"] = minimum_settings["short_match_cutoff"]
            elif minimum != "FilteredSix":
                raise ValueError(f"Unknown lazy minimum: {minimum}")
        else:
            fields["max_dist_3_matches"] = parser_settings["short_match_cutoff"]
    return fields
