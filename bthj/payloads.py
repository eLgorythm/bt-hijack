from __future__ import annotations

import re

TOKEN_RE = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")


def apply_vars(text: str, variables: dict[str, str] | None = None) -> str:
    variables = variables or {}
    return TOKEN_RE.sub(lambda m: variables.get(m.group(1), m.group(0)), text)


def missing_tokens(text: str) -> list[str]:
    tokens = []
    seen = set()
    for m in TOKEN_RE.finditer(text):
        if m.group(1) not in seen:
            seen.add(m.group(1))
            tokens.append(m.group(1))
    return tokens


def parse_vars(arg_vars: list[str]) -> dict[str, str]:
    variables: dict[str, str] = {}
    for item in arg_vars or []:
        if "=" not in item:
            raise ValueError(f"bad --var entry: {item!r} (want NAME=value)")
        key, _, value = item.partition("=")
        key = key.strip()
        if not key:
            raise ValueError(f"empty variable name in: {item!r}")
        variables[key] = value
    return variables


def load_payload(
    text: str | None = None,
    path: str | None = None,
    variables: dict[str, str] | None = None,
) -> str:
    if text is not None and path is not None:
        raise ValueError("use only one of text/script or script-file")
    if path is not None:
        with open(path, "r") as fh:
            text = fh.read()
    text = text or ""
    return apply_vars(text, variables)