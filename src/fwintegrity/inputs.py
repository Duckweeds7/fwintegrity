"""Load audit / ticket tables from CSV text or pre-built ``Mapping`` rows."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .ticket import slugify_column_name


def _row_str(m: Mapping[str, Any]) -> dict[str, str]:
    return {slugify_column_name(str(k)): ("" if v is None else str(v)).strip() for k, v in m.items()}


def load_audit_table(audit: str | Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    if isinstance(audit, str):
        from .audit_report import parse_audit_report_text

        return parse_audit_report_text(audit)
    return [_row_str(r) for r in audit]


def load_ticket_table(
    tickets: str | Iterable[Mapping[str, Any]] | Iterable[Iterable[Mapping[str, Any]]],
) -> list[dict[str, str]]:
    if isinstance(tickets, str):
        from .ticket import parse_ticket_csv_text

        return parse_ticket_csv_text(tickets)
    seq: list[Any] = list(tickets)
    if not seq:
        return []
    if isinstance(seq[0], Mapping):
        return [_row_str(t) for t in seq]
    out: list[dict[str, str]] = []
    for batch in seq:
        for row in batch:
            out.append(_row_str(row))
    return out
