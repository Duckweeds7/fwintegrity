"""Match normalized audit rows to ticket rows (bidirectional containment, optional kind matrix)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import ipaddress

from .models import (
    AddrCompound,
    AddrLiteral,
    AddrRef,
    ChangeKind,
    NormalizedChange,
    PortInterval,
    ServiceBundle,
    ServiceCompound,
    ServiceLiteral,
    ServiceRef,
)
from .ignore_lists import service_spec_ignored
from .normalize import merge_port_intervals

DEFAULT_AUDIT_TO_TICKET_KINDS: dict[ChangeKind, frozenset[ChangeKind]] = {
    ChangeKind.ADD: frozenset({ChangeKind.ADD}),
    ChangeKind.MODIFY: frozenset({ChangeKind.MODIFY, ChangeKind.DISABLED}),
    ChangeKind.REMOVE: frozenset({ChangeKind.REMOVE}),
    ChangeKind.DISABLED: frozenset({ChangeKind.DISABLED, ChangeKind.MODIFY}),
}


def _addr_literal_covers(outer: AddrLiteral, inner: AddrLiteral) -> bool:
    outer_nets = [ipaddress.ip_network(x, strict=False) for x in outer.networks]
    for t in inner.networks:
        tnet = ipaddress.ip_network(t, strict=False)
        if not any(tnet.subnet_of(on) or tnet == on for on in outer_nets):
            return False
    return True


def _to_compound(ep: AddrLiteral | AddrRef | AddrCompound) -> AddrCompound:
    if isinstance(ep, AddrCompound):
        return ep
    if isinstance(ep, AddrLiteral):
        return AddrCompound(ep.networks, ())
    return AddrCompound((), (ep.name.strip(),))


def _compound_covers(outer: AddrCompound, inner: AddrCompound) -> bool:
    if inner.networks:
        if not outer.networks:
            return False
        if not _addr_literal_covers(
            AddrLiteral(tuple(inner.networks)),
            AddrLiteral(tuple(outer.networks)),
        ):
            return False
    if inner.objects:
        oset = {x.casefold() for x in outer.objects}
        for o in inner.objects:
            if o.casefold() not in oset:
                return False
    return True


def endpoint_covers(outer: AddrLiteral | AddrRef | AddrCompound, inner: AddrLiteral | AddrRef | AddrCompound) -> bool:
    return _compound_covers(_to_compound(outer), _to_compound(inner))


def endpoint_match(
    a: AddrLiteral | AddrRef | AddrCompound, b: AddrLiteral | AddrRef | AddrCompound
) -> bool:
    return endpoint_covers(a, b) and endpoint_covers(b, a)


def _interval_subset(inner: tuple[PortInterval, ...], outer: tuple[PortInterval, ...]) -> bool:
    for i in inner:
        ok = False
        for o in outer:
            if i.start >= o.start and i.end <= o.end:
                ok = True
                break
        if not ok:
            return False
    return True


def _service_covers_simple(
    outer: ServiceLiteral | ServiceRef | ServiceBundle,
    inner: ServiceLiteral | ServiceRef | ServiceBundle,
) -> bool:
    if isinstance(inner, ServiceRef):
        return isinstance(outer, ServiceRef) and outer.name.casefold() == inner.name.casefold()
    if isinstance(inner, ServiceBundle):
        if isinstance(outer, ServiceRef):
            return False
        return all(_service_covers_simple(outer, p) for p in inner.parts)
    if isinstance(inner, ServiceLiteral):
        if isinstance(outer, ServiceRef):
            return False
        parts: list[ServiceLiteral] = list(outer.parts) if isinstance(outer, ServiceBundle) else [outer]
        same = [p for p in parts if p.proto.casefold() == inner.proto.casefold()]
        if not same:
            return False
        merged_iv = merge_port_intervals([iv for p in same for iv in p.intervals])
        return _interval_subset(inner.intervals, merged_iv)
    return False


def _bundle_from_literals(lits: tuple[ServiceLiteral, ...]) -> ServiceLiteral | ServiceBundle:
    if len(lits) == 1:
        return lits[0]
    return ServiceBundle(lits)


def _to_service_compound(svc: ServiceLiteral | ServiceRef | ServiceBundle | ServiceCompound) -> ServiceCompound:
    if isinstance(svc, ServiceCompound):
        return svc
    if isinstance(svc, ServiceRef):
        return ServiceCompound((), (svc.name.strip(),))
    if isinstance(svc, ServiceLiteral):
        return ServiceCompound((svc,), ())
    return ServiceCompound(svc.parts, ())


def _compound_service_covers(outer: ServiceCompound, inner: ServiceCompound) -> bool:
    if inner.literals:
        if not outer.literals:
            return False
        o_agg = _bundle_from_literals(outer.literals)
        for lit in inner.literals:
            if not _service_covers_simple(o_agg, lit):
                return False
    if inner.objects:
        oset = {x.casefold() for x in outer.objects}
        for o in inner.objects:
            if o.casefold() not in oset:
                return False
    return True


def service_covers(
    outer: ServiceLiteral | ServiceRef | ServiceBundle | ServiceCompound,
    inner: ServiceLiteral | ServiceRef | ServiceBundle | ServiceCompound,
) -> bool:
    return _compound_service_covers(_to_service_compound(outer), _to_service_compound(inner))


def service_match(
    a: ServiceLiteral | ServiceRef | ServiceBundle | ServiceCompound,
    b: ServiceLiteral | ServiceRef | ServiceBundle | ServiceCompound,
) -> bool:
    return service_covers(a, b) and service_covers(b, a)


def change_kinds_compatible(
    audit: ChangeKind,
    ticket: ChangeKind,
    matrix: dict[ChangeKind, frozenset[ChangeKind]] | None = None,
) -> bool:
    m = matrix or DEFAULT_AUDIT_TO_TICKET_KINDS
    allowed = m.get(audit)
    if allowed is None:
        return audit == ticket
    return ticket in allowed


def _service_dim_match(
    a: ServiceLiteral | ServiceRef | ServiceBundle | ServiceCompound,
    b: ServiceLiteral | ServiceRef | ServiceBundle | ServiceCompound,
    ignored_services: frozenset[str] | None,
) -> bool:
    if service_spec_ignored(a, ignored_services) or service_spec_ignored(b, ignored_services):
        return True
    return service_covers(a, b) or service_covers(b, a)


def change_match(
    audit: NormalizedChange,
    ticket: NormalizedChange,
    matrix: dict[ChangeKind, frozenset[ChangeKind]] | None = None,
    ignored_services: frozenset[str] | None = None,
) -> bool:
    if not change_kinds_compatible(audit.change, ticket.change, matrix):
        return False
    inner_in_outer = (
        endpoint_covers(audit.source, ticket.source)
        and endpoint_covers(audit.destination, ticket.destination)
        and _service_dim_match(audit.service, ticket.service, ignored_services)
    )
    outer_in_inner = (
        endpoint_covers(ticket.source, audit.source)
        and endpoint_covers(ticket.destination, audit.destination)
        and _service_dim_match(ticket.service, audit.service, ignored_services)
    )
    return inner_in_outer or outer_in_inner


@dataclass
class CompareResult:
    matched: list[tuple[NormalizedChange, NormalizedChange]]
    audit_only: list[NormalizedChange]
    ticket_only: list[NormalizedChange]


def compare_changes(
    audit_rows: list[NormalizedChange],
    ticket_rows: list[NormalizedChange],
    matrix: dict[ChangeKind, frozenset[ChangeKind]] | None = None,
    ignored_services: frozenset[str] | None = None,
) -> CompareResult:
    matched: list[tuple[NormalizedChange, NormalizedChange]] = []
    used_tickets: set[int] = set()
    matched_audit_idx: set[int] = set()
    matched_ticket_idx: set[int] = set()
    for i, a in enumerate(audit_rows):
        for j, t in enumerate(ticket_rows):
            if j in used_tickets:
                continue
            if change_match(a, t, matrix, ignored_services):
                used_tickets.add(j)
                matched.append((a, t))
                matched_audit_idx.add(i)
                matched_ticket_idx.add(j)
                break
    audit_only = [a for i, a in enumerate(audit_rows) if i not in matched_audit_idx]
    ticket_only = [t for j, t in enumerate(ticket_rows) if j not in matched_ticket_idx]
    return CompareResult(matched=matched, audit_only=audit_only, ticket_only=ticket_only)


@dataclass(frozen=True)
class AuditRuleRequestLink:
    audit_row_index: int
    audit: NormalizedChange | None
    inf_numbers: tuple[str, ...]
    ticket_numbers: tuple[str, ...] = ()
    audit_parse_messages: tuple[str, ...] = ()
    matched_ticket_row_indices: tuple[int, ...] = ()


def link_audit_to_ticket_requests(
    audit: str | Iterable[Mapping[str, Any]],
    tickets: (
        str
        | Iterable[Mapping[str, Any]]
        | Iterable[Iterable[Mapping[str, Any]]]
    ),
    matrix: dict[ChangeKind, frozenset[ChangeKind]] | None = None,
    ignored_services: frozenset[str] | None = None,
) -> list[AuditRuleRequestLink]:
    from .audit_report import iter_audit_rows_normalized
    from .inputs import load_audit_table, load_ticket_table
    from .ticket import iter_ticket_rows_normalized

    audit_rows = load_audit_table(audit)
    ticket_rows = load_ticket_table(tickets)
    labeled_tickets = list(iter_ticket_rows_normalized(ticket_rows))
    out: list[AuditRuleRequestLink] = []
    for ai, a_ch, a_issues in iter_audit_rows_normalized(audit_rows):
        msgs = tuple(x.message for x in a_issues)
        if a_ch is None:
            out.append(AuditRuleRequestLink(ai, None, (), (), msgs, ()))
            continue
        inf_ids: list[str] = []
        tkt_ids: list[str] = []
        tidxs: list[int] = []
        for tj, t_ch, _t_iss, tnum, inum in labeled_tickets:
            if t_ch is None:
                continue
            if change_match(a_ch, t_ch, matrix, ignored_services):
                if inum and inum not in inf_ids:
                    inf_ids.append(inum)
                if tnum and tnum not in tkt_ids:
                    tkt_ids.append(tnum)
                tidxs.append(tj)
        out.append(
            AuditRuleRequestLink(
                ai, a_ch, tuple(inf_ids), tuple(tkt_ids), msgs, tuple(tidxs)
            )
        )
    return out
