"""ICMP / ping style service names skipped in matching and triple generation."""

from __future__ import annotations

from .models import ServiceBundle, ServiceCompound, ServiceLiteral, ServiceRef

DEFAULT_IGNORED_SERVICE_NAMES: frozenset[str] = frozenset(
    {
        "icmp",
        "icmp/8",
        "icmp/0",
        "icmpv6",
        "ping",
        "echo-request",
        "echo-reply",
        "echorequest",
        "echoreply",
    }
)


def merged_ignored_service_names(extra: frozenset[str] | None) -> frozenset[str]:
    return DEFAULT_IGNORED_SERVICE_NAMES | (extra or frozenset())


def _norm_service_name(s: str) -> str:
    t = s.strip().lower().replace(" ", "").replace("_", "/")
    return t


def service_name_ignored(name: str, extra: frozenset[str] | None = None) -> bool:
    n = _norm_service_name(name)
    if not n:
        return False
    m = merged_ignored_service_names(extra)
    if n in m:
        return True
    for k in m:
        if k and (n == k or n.startswith(f"{k}/") or n.startswith(f"{k}:")):
            return True
    if n.startswith("icmp"):
        return True
    if n == "ping" or n.startswith("ping/"):
        return True
    return False


def service_spec_ignored(
    svc: ServiceLiteral | ServiceRef | ServiceBundle | ServiceCompound | None,
    extra: frozenset[str] | None = None,
) -> bool:
    if svc is None:
        return False
    if isinstance(svc, ServiceRef):
        return service_name_ignored(svc.name, extra)
    if isinstance(svc, ServiceLiteral):
        if svc.proto.casefold() in {"icmp", "icmpv6"}:
            return True
        return False
    if isinstance(svc, ServiceCompound):
        return all(service_spec_ignored(p, extra) for p in svc.literals) and all(
            service_name_ignored(o, extra) for o in svc.objects
        )
    return all(service_spec_ignored(p, extra) for p in svc.parts)
