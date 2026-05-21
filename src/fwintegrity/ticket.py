"""Change-ticket CSV parsing and row → ``NormalizedChange`` mapping."""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterable, Mapping
from typing import Any

from .models import ChangeKind, NormalizedChange, ParseIssue, ParsedField
from .normalize import normalize_change_kind, parse_endpoint_text, parse_ticket_service_field


def slugify_column_name(h: str) -> str:
    t = h.strip().lower().replace(" ", "_")
    t = re.sub(r"[^a-z0-9_]+", "", t)
    return t


# First non-empty value among these slugged keys becomes ``ticket_number_from_row`` result.
_TICKET_NUMBER_KEYS = (
    "ticket_number",
    "ticketnumber",
    "work_order_number",
    "workordernumber",
    "changerequestnumber",
    "change_request_number",
    "chg_number",
    "chg",
    "crq_number",
    "crq",
    "ritm_number",
    "ritm",
    "parent_request",
    "parent",
)


def ticket_number_from_row(row: Mapping[str, str]) -> str:
    for k in _TICKET_NUMBER_KEYS:
        v = str(row.get(k, "")).strip()
        if v:
            return v
    return ""


def inf_number_from_row(row: Mapping[str, str]) -> str:
    for k in ("inf_number", "infnumber"):
        v = str(row.get(k, "")).strip()
        if v:
            return v
    v = str(row.get("item", "")).strip()
    if v:
        return v
    return ""


def ticket_request_id(row: Mapping[str, str]) -> str:
    return inf_number_from_row(row)


def parse_ticket_csv_text(text: str) -> list[dict[str, str]]:
    buf = text.lstrip("\ufeff")
    sample = buf[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        reader = csv.reader(io.StringIO(buf), dialect)
    except csv.Error:
        reader = csv.reader(io.StringIO(buf))
    rows = list(reader)
    if not rows:
        return []
    keys = [slugify_column_name(c) for c in rows[0]]
    out: list[dict[str, str]] = []
    for parts in rows[1:]:
        row = {keys[i]: (parts[i].strip() if i < len(parts) else "") for i in range(len(keys))}
        if any(row.values()):
            out.append(row)
    return out


def parse_action_field(raw: str) -> ParsedField:
    ck = normalize_change_kind(raw)
    if ck:
        return ParsedField(raw, ck, "high")
    return ParsedField(raw, None, "low", issues=[ParseIssue("unknown_action")])


def row_to_normalized_change(row: Mapping[str, str]) -> tuple[NormalizedChange | None, list[ParseIssue]]:
    issues: list[ParseIssue] = []
    r = {slugify_column_name(k): str(v).strip() for k, v in row.items()}
    ck_raw = (
        r.get("change_type", "")
        or r.get("action", "")
        or r.get("changetype", "")
    ).strip()
    af = parse_action_field(ck_raw)
    if af.normalized is None:
        has_endpoints = bool(
            (r.get("source", "") or r.get("source_ip_address", "")).strip()
            or (r.get("destination", "") or r.get("destination_ip_address", "")).strip()
        )
        if not ck_raw and has_endpoints:
            change = ChangeKind.ADD
            issues.append(ParseIssue("default_action_add"))
        else:
            issues.extend(af.issues)
            return None, issues
    else:
        try:
            change = ChangeKind(af.normalized)
        except ValueError:
            issues.append(ParseIssue("invalid_action"))
            return None, issues
    src = parse_endpoint_text(
        (r.get("source", "") or r.get("source_ip_address", "")).strip()
    )
    dst = parse_endpoint_text(
        (r.get("destination", "") or r.get("destination_ip_address", "")).strip()
    )
    svc = parse_ticket_service_field((r.get("service", "") or r.get("service_port", "")).strip())
    if src is None:
        issues.append(ParseIssue("missing_source"))
    if dst is None:
        issues.append(ParseIssue("missing_destination"))
    if svc is None:
        issues.append(ParseIssue("missing_service"))
    if src is None or dst is None or svc is None:
        return None, issues
    return NormalizedChange(change, src, dst, svc, meta=tuple(sorted(r.items()))), issues


def rows_to_normalized_changes(rows: Iterable[dict[str, str]]) -> list[tuple[NormalizedChange, list[ParseIssue]]]:
    out: list[tuple[NormalizedChange, list[ParseIssue]]] = []
    for row in rows:
        ch, iss = row_to_normalized_change(row)
        if ch is not None:
            out.append((ch, iss))
    return out


def iter_ticket_rows_normalized(
    rows: Iterable[Mapping[str, Any]],
) -> list[tuple[int, NormalizedChange | None, list[ParseIssue], str, str]]:
    out: list[tuple[int, NormalizedChange | None, list[ParseIssue], str, str]] = []
    for j, row in enumerate(rows):
        r = {slugify_column_name(str(k)): ("" if v is None else str(v)).strip() for k, v in row.items()}
        ch, iss = row_to_normalized_change(r)
        tnum = ticket_number_from_row(r)
        inum = inf_number_from_row(r)
        out.append((j, ch, iss, tnum, inum))
    return out
