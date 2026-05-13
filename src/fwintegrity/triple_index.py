"""Atomic keys for (source, destination, service) triple indexing and lookup."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import product

from .ignore_lists import service_spec_ignored
from .models import AddrCompound, AddrLiteral, AddrRef, NormalizedChange, ServiceBundle, ServiceCompound, ServiceLiteral, ServiceRef


def endpoint_atom_keys(ep: AddrLiteral | AddrRef | AddrCompound) -> list[str]:
    if isinstance(ep, AddrCompound):
        return sorted(
            [f"i:{n}" for n in ep.networks]
            + [f"g:{o.strip().casefold()}" for o in ep.objects]
        )
    if isinstance(ep, AddrRef):
        return [f"g:{ep.name.strip().casefold()}"]
    return [f"i:{n}" for n in ep.networks]


def service_atom_keys(
    svc: ServiceLiteral | ServiceRef | ServiceBundle | ServiceCompound,
    ignored_services: frozenset[str] | None = None,
) -> list[str]:
    if service_spec_ignored(svc, ignored_services):
        return []
    if isinstance(svc, ServiceCompound):
        keys: list[str] = []
        for p in svc.literals:
            for iv in p.intervals:
                if iv.start == iv.end:
                    keys.append(f"s:{p.proto.casefold()}:{iv.start}")
                else:
                    keys.append(f"s:{p.proto.casefold()}:{iv.start}-{iv.end}")
        for o in svc.objects:
            keys.append(f"sr:g:{o.strip().casefold()}")
        return sorted(set(keys))
    if isinstance(svc, ServiceRef):
        return [f"sr:g:{svc.name.strip().casefold()}"]
    if isinstance(svc, ServiceLiteral):
        parts: list[ServiceLiteral] = [svc]
    else:
        parts = list(svc.parts)
    keys: list[str] = []
    for p in parts:
        for iv in p.intervals:
            if iv.start == iv.end:
                keys.append(f"s:{p.proto.casefold()}:{iv.start}")
            else:
                keys.append(f"s:{p.proto.casefold()}:{iv.start}-{iv.end}")
    return sorted(set(keys))


def iter_change_triples(
    change: NormalizedChange,
    max_triples: int,
    ignored_services: frozenset[str] | None = None,
):
    sk = endpoint_atom_keys(change.source)
    dk = endpoint_atom_keys(change.destination)
    vk = service_atom_keys(change.service, ignored_services)
    n = len(sk) * len(dk) * len(vk)
    if n > max_triples:
        raise ValueError(f"triple product {n} exceeds max_triples {max_triples}")
    yield from product(sk, dk, vk)


@dataclass(frozen=True)
class TripleHit:
    ticket_number: str
    inf_number: str
    ticket_row_index: int


class TicketTripleIndex:
    def __init__(
        self,
        max_triples_per_row: int = 50_000,
        ignored_services: frozenset[str] | None = None,
    ) -> None:
        self._m: dict[tuple[str, str, str], list[TripleHit]] = defaultdict(list)
        self.max_triples_per_row = max_triples_per_row
        self.ignored_services = ignored_services

    def index_ticket_row(
        self,
        change: NormalizedChange,
        ticket_number: str,
        inf_number: str,
        row_index: int,
    ) -> int:
        hit = TripleHit(ticket_number, inf_number, row_index)
        n = 0
        for tri in iter_change_triples(
            change, self.max_triples_per_row, self.ignored_services
        ):
            self._m[tri].append(hit)
            n += 1
        return n

    def lookup(self, triple: tuple[str, str, str]) -> list[TripleHit]:
        return list(self._m.get(triple, ()))

    def __contains__(self, triple: tuple[str, str, str]) -> bool:
        return triple in self._m


def build_ticket_triple_index(
    ticket_rows: list[dict[str, str]],
    max_triples_per_row: int = 50_000,
    ignored_services: frozenset[str] | None = None,
) -> TicketTripleIndex:
    from .ticket import iter_ticket_rows_normalized

    idx = TicketTripleIndex(max_triples_per_row, ignored_services)
    for j, ch, _iss, tnum, inum in iter_ticket_rows_normalized(ticket_rows):
        if ch is None:
            continue
        idx.index_ticket_row(ch, tnum, inum, j)
    return idx


def audit_triples_all_in_index(
    audit: NormalizedChange,
    index: TicketTripleIndex,
    max_triples: int = 500_000,
    ignored_services: frozenset[str] | None = None,
) -> tuple[bool, list[tuple[str, str, str]]]:
    missing: list[tuple[str, str, str]] = []
    ign = ignored_services if ignored_services is not None else index.ignored_services
    for tri in iter_change_triples(audit, max_triples, ign):
        if tri not in index:
            missing.append(tri)
    return (not missing, missing)
