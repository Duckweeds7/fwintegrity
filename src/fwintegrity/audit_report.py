"""Parse audit policy export tables (CSV / TSV / wide-space) into row dicts."""

from __future__ import annotations

import csv
import io
import re
from typing import Iterable

from .models import ChangeKind, NormalizedChange, ParseIssue
from .normalize import (
    normalize_change_kind,
    parse_audit_report_endpoint,
    parse_audit_report_service,
)

# Slugged CSV header (see ``_slug_header``) → keys on each row dict consumed by ``audit_row_to_normalized``.
_CANON = {
    "hostname": "hostname",
    "change_type": "change_type",
    "policy": "policy",
    "number": "number",
    "name": "name",
    "scope": "scope",
    "status": "status",
    "source_zone": "source_zone",
    "source": "source",
    "user": "user",
    "destination_zone": "destination_zone",
    "destination": "destination",
    "application": "application",
    "service": "service",
    "url_category": "url_category",
    "action": "action",
    "security_profile": "security_profile",
    "tcp_falgs": "tcp_flags",
    "tcp_flags": "tcp_flags",
    "schedule_object": "schedule_object",
    "logging": "logging",
    "vendor_tag": "vendor_tag",
}


def _slug_header(h: str) -> str:
    t = h.strip().lower().replace(" ", "_")
    t = re.sub(r"[^a-z0-9_]+", "", t)
    return t


def _map_header(cells: list[str]) -> list[str | None]:
    out: list[str | None] = []
    for c in cells:
        s = _slug_header(c)
        out.append(_CANON.get(s))
    return out


def _split_wide_ws(line: str) -> list[str]:
    return [p.strip() for p in re.split(r"\s{2,}", line.rstrip("\n")) if p.strip()]


def _read_rows(text: str) -> tuple[list[str | None], list[list[str]]]:
    sample = text.lstrip("\ufeff")[:4096]
    if "\t" in sample.splitlines()[0] if sample else False:
        r = csv.reader(io.StringIO(text.lstrip("\ufeff")), delimiter="\t")
        rows = list(r)
    else:
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
            r = csv.reader(io.StringIO(text.lstrip("\ufeff")), dialect)
            rows = list(r)
        except csv.Error:
            rows = [ln.split(",") for ln in text.lstrip("\ufeff").splitlines() if ln.strip()]
    if not rows:
        return [], []
    if len(rows[0]) == 1 and "," not in rows[0][0] and re.search(r"\s{2,}", rows[0][0]):
        lines = [r[0] for r in rows]
        header = _split_wide_ws(lines[0])
        mapped = _map_header(header)
        if not all(m is None for m in mapped):
            body = [_split_wide_ws(ln) for ln in lines[1:]]
            return mapped, body
    header = [c.strip() for c in rows[0]]
    mapped = _map_header(header)
    if all(m is None for m in mapped):
        header = _split_wide_ws(rows[0][0]) if len(rows[0]) == 1 else _split_wide_ws(
            "\t".join(rows[0])
        )
        if not header:
            header = [c.strip() for c in rows[0]]
        mapped = _map_header(header)
        body = []
        for line in rows[1:]:
            s = line[0] if len(line) == 1 else "\t".join(line)
            body.append(_split_wide_ws(s) if "\t" not in s else s.split("\t"))
    else:
        body = rows[1:]
    return mapped, body


def parse_audit_report_text(text: str) -> list[dict[str, str]]:
    mapped, body = _read_rows(text)
    if not mapped:
        return []
    idx = {name: i for i, name in enumerate(mapped) if name}
    out: list[dict[str, str]] = []
    for parts in body:
        row: dict[str, str] = {}
        for k, i in idx.items():
            row[k] = parts[i].strip() if i < len(parts) else ""
        out.append(row)
    return out


def audit_row_to_normalized(row: dict[str, str]) -> tuple[NormalizedChange | None, list[ParseIssue]]:
    issues: list[ParseIssue] = []
    ck = normalize_change_kind(row.get("change_type", ""))
    if not ck:
        issues.append(ParseIssue("missing_change_type"))
        return None, issues
    try:
        change = ChangeKind(ck)
    except ValueError:
        issues.append(ParseIssue("invalid_change_type"))
        return None, issues
    src = parse_audit_report_endpoint(row.get("source", ""))
    dst = parse_audit_report_endpoint(row.get("destination", ""))
    svc = parse_audit_report_service(row.get("service", ""))
    if src is None:
        issues.append(ParseIssue("missing_source"))
    if dst is None:
        issues.append(ParseIssue("missing_destination"))
    if svc is None:
        issues.append(ParseIssue("missing_service"))
    if src is None or dst is None or svc is None:
        return None, issues
    meta_items = tuple(
        sorted((k, v) for k, v in row.items() if k in {"hostname", "policy", "number", "name"})
    )
    return NormalizedChange(change, src, dst, svc, meta=meta_items), issues


def rows_to_normalized_changes(rows: Iterable[dict[str, str]]) -> list[NormalizedChange]:
    res: list[NormalizedChange] = []
    for row in rows:
        ch, _iss = audit_row_to_normalized(row)
        if ch is not None:
            res.append(ch)
    return res


def iter_audit_rows_normalized(
    rows: Iterable[dict[str, str]],
) -> list[tuple[int, NormalizedChange | None, list[ParseIssue]]]:
    out: list[tuple[int, NormalizedChange | None, list[ParseIssue]]] = []
    for i, row in enumerate(rows):
        ch, iss = audit_row_to_normalized(row)
        out.append((i, ch, iss))
    return out