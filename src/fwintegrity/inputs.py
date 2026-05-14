"""Load audit / ticket tables from CSV text or pre-built ``Mapping`` rows."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .table_load import (
    ChangeRowMapping,
    from_csv_text,
    from_dict_rows,
    load_change_rows,
)
from .ticket import slugify_column_name


def _row_str(m: Mapping[str, Any]) -> dict[str, str]:
    return {slugify_column_name(str(k)): ("" if v is None else str(v)).strip() for k, v in m.items()}


def load_audit_table(
    audit: str | Path | Iterable[Mapping[str, Any]],
    *,
    mapping: ChangeRowMapping | None = None,
) -> list[dict[str, str]]:
    if isinstance(audit, Path):
        if mapping is None:
            from .audit_report import parse_audit_report_text

            return parse_audit_report_text(audit.read_text(encoding="utf-8"))
        return load_change_rows(from_csv_text(audit.read_text(encoding="utf-8")), mapping)
    if isinstance(audit, str):
        if mapping is None:
            from .audit_report import parse_audit_report_text

            return parse_audit_report_text(audit)
        return load_change_rows(from_csv_text(audit), mapping)
    rows = list(audit)
    if mapping is None:
        return [_row_str(r) for r in rows]
    return load_change_rows(from_dict_rows(rows), mapping)


def load_ticket_table(
    tickets: str | Path | Iterable[Mapping[str, Any]] | Iterable[Iterable[Mapping[str, Any]]],
    *,
    mapping: ChangeRowMapping | None = None,
) -> list[dict[str, str]]:
    if isinstance(tickets, Path):
        if mapping is None:
            from .ticket import parse_ticket_csv_text

            return parse_ticket_csv_text(tickets.read_text(encoding="utf-8"))
        return load_change_rows(from_csv_text(tickets.read_text(encoding="utf-8")), mapping)
    if isinstance(tickets, str):
        if mapping is None:
            from .ticket import parse_ticket_csv_text

            return parse_ticket_csv_text(tickets)
        return load_change_rows(from_csv_text(tickets), mapping)
    seq: list[Any] = list(tickets)
    if not seq:
        return []
    if isinstance(seq[0], Mapping):
        rows = seq
        if mapping is None:
            return [_row_str(t) for t in rows]
        return load_change_rows(from_dict_rows(rows), mapping)
    out: list[dict[str, str]] = []
    for batch in seq:
        rows = list(batch)
        if mapping is None:
            out.extend(_row_str(row) for row in rows)
        else:
            out.extend(load_change_rows(from_dict_rows(rows), mapping))
    return out
