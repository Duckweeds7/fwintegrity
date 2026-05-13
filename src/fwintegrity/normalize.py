"""String normalization: endpoints (IP/CIDR, prefixed audit tokens, object names), services (ports, compounds).

Prefixed export-token shapes live in regexes prefixed with ``_AUD_`` and in
``expand_audit_network_token``.  Loose ticket service strings are scanned by
``_iter_loose_tcp_udp_segments`` so object/group names may appear between
``TCP``/``UDP`` clauses without breaking port parsing.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata

from .models import (
    AddrCompound,
    AddrLiteral,
    AddrRef,
    PortInterval,
    ServiceBundle,
    ServiceCompound,
    ServiceLiteral,
    ServiceRef,
)

_WS_RE = re.compile(r"\s+")
_PORT_TOKEN_RE = re.compile(
    r"(?P<proto>tcp|udp|TCP|UDP)?\s*[:/]?\s*(?P<ports>[0-9,\s\-–—~]+)",
    re.UNICODE,
)


def unicode_fold_punct(text: str) -> str:
    t = unicodedata.normalize("NFKC", text)
    t = t.replace("，", ",").replace("；", ";").replace("：", ":")
    t = t.replace("–", "-").replace("—", "-").replace("~", "-")
    return t.strip()


def merge_port_intervals(intervals: list[PortInterval]) -> tuple[PortInterval, ...]:
    if not intervals:
        return ()
    items = sorted((p.start, p.end) for p in intervals)
    acc: list[tuple[int, int]] = [items[0]]
    for c, d in items[1:]:
        a, b = acc[-1]
        if c <= b + 1:
            acc[-1] = (a, max(b, d))
        else:
            acc.append((c, d))
    return tuple(PortInterval(a, b) for a, b in acc)


def parse_port_list_blob(blob: str) -> list[PortInterval]:
    s = unicode_fold_punct(blob)
    s = s.replace(";", ",")
    parts = [p.strip() for p in re.split(r"[,/\s]+", s) if p.strip()]
    out: list[PortInterval] = []
    for p in parts:
        m = re.fullmatch(r"(\d+)\s*-\s*(\d+)", p)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            out.append(PortInterval(min(a, b), max(a, b)))
            continue
        if p.isdigit():
            v = int(p)
            out.append(PortInterval(v, v))
    return out


def parse_service_text(text: str) -> ServiceLiteral | ServiceRef | None:
    raw = text.strip()
    if not raw:
        return None
    m = _PORT_TOKEN_RE.search(raw)
    if m and m.group("ports"):
        proto = (m.group("proto") or "tcp").lower()
        intervals = merge_port_intervals(parse_port_list_blob(m.group("ports")))
        if intervals:
            return ServiceLiteral(proto, intervals)
    if re.fullmatch(r"[A-Za-z0-9_.\-]+", raw):
        return ServiceRef(raw)
    intervals = merge_port_intervals(parse_port_list_blob(raw))
    if intervals:
        return ServiceLiteral("tcp", intervals)
    return ServiceRef(raw)


_PORT_CHARS = frozenset("0123456789,-–—~/+ \t")


def _iter_loose_tcp_udp_segments(raw: str) -> list[tuple[int, int, str, str]]:
    """Return (abs_start, abs_end, proto, port_blob) for each TCP/UDP clause in *raw*.

    Port blob stops at the first character not in ``_PORT_CHARS`` so names like
    ``APP_Group`` between clauses are not swallowed as ports.
    """
    out: list[tuple[int, int, str, str]] = []
    i = 0
    while i < len(raw):
        sub = raw[i:]
        m = re.search(r"(?i)\b(TCP|UDP)\b", sub)
        if not m:
            break
        abs_start = i + m.start()
        proto = m.group(1).lower()
        j = i + m.end()
        while j < len(raw) and raw[j] in " \t_":
            j += 1
        k = j
        while k < len(raw) and raw[k] in _PORT_CHARS:
            k += 1
        blob = raw[j:k].strip().rstrip(",")
        if not blob or not any(c.isdigit() for c in blob):
            return []
        out.append((abs_start, k, proto, blob))
        i = k
    return out


def parse_loose_service_field(
    text: str,
) -> ServiceLiteral | ServiceRef | ServiceBundle | ServiceCompound | None:
    raw = unicode_fold_punct(text)
    if not raw:
        return None
    segs = _iter_loose_tcp_udp_segments(raw)
    if not segs:
        return None
    by_proto: dict[str, list[PortInterval]] = {}
    for _start, _end, proto, blob in segs:
        iv = merge_port_intervals(parse_port_list_blob(blob))
        if not iv:
            return ServiceRef(text)
        by_proto.setdefault(proto, []).extend(iv)
    parts: list[ServiceLiteral] = []
    for pkey in sorted(by_proto.keys()):
        merged = merge_port_intervals(by_proto[pkey])
        parts.append(ServiceLiteral(pkey, merged))
    objects: list[str] = []
    pos = 0
    for start, end, _, _ in segs:
        gap = raw[pos:start].strip()
        if gap:
            for piece in re.split(r"[,;\s]+", gap):
                p = piece.strip()
                if p:
                    objects.append(p)
        pos = end
    gap = raw[pos:].strip()
    if gap:
        for piece in re.split(r"[,;\s]+", gap):
            p = piece.strip()
            if p:
                objects.append(p)
    lit_tuple = tuple(parts)
    obj_tuple = tuple(objects)
    if lit_tuple and obj_tuple:
        return ServiceCompound(lit_tuple, obj_tuple)
    if len(lit_tuple) == 1:
        return lit_tuple[0]
    return ServiceBundle(lit_tuple)


def parse_ticket_service_field(
    text: str,
) -> ServiceLiteral | ServiceRef | ServiceBundle | ServiceCompound | None:
    t = text.strip()
    if not t:
        return None
    loose = parse_loose_service_field(t)
    if loose is not None:
        return loose
    return parse_service_text(t)


def parse_endpoint_text(text: str) -> AddrLiteral | AddrRef | AddrCompound | None:
    """Parse a ticket-style endpoint cell: IPs/CIDRs plus optional object/group tokens."""
    raw = text.strip()
    if not raw:
        return None
    tokens = [t.strip() for t in re.split(r"[,;\s]+", raw) if t.strip()]
    if not tokens:
        tokens = [raw]
    expanded: list[str] = []
    objects: list[str] = []
    for token in tokens:
        xs = expand_audit_network_token(token)
        if xs:
            expanded.extend(xs)
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
            expanded.append(str(net))
        except ValueError:
            try:
                ip = ipaddress.ip_address(token)
                expanded.append(str(ipaddress.ip_network(f"{ip}/32", strict=False)))
            except ValueError:
                ot = _WS_RE.sub(" ", token.strip())
                if ot:
                    objects.append(ot)
    merged_nets = merge_ip_network_strings(expanded) if expanded else []
    if merged_nets and objects:
        return AddrCompound(tuple(merged_nets), tuple(objects))
    if merged_nets:
        return AddrLiteral(tuple(merged_nets))
    if objects:
        if len(objects) == 1:
            return AddrRef(objects[0])
        return AddrCompound((), tuple(objects))
    return AddrRef(_WS_RE.sub(" ", raw))


def merge_ip_network_strings(networks: list[str]) -> list[str]:
    nets = [ipaddress.ip_network(n, strict=False) for n in networks]
    return [str(x) for x in ipaddress.collapse_addresses(sorted(nets))]


_P_STRIP = re.compile(r"(?i)^(ip_range|ranges?|range)_(.+)$")
_AUD_IPV4_DASH_RANGE = re.compile(r"(?i)^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$")
_AUD_LAST_OCTET_RANGE = re.compile(r"(?i)^((?:\d{1,3}\.){3})(\d+)-(\d+)$")


def _expand_two_ipv4(a: str, b: str) -> list[str]:
    """Expand inclusive IPv4 range; empty if more than 513 hosts (DoS guard)."""
    ia, ib = ipaddress.ip_address(a), ipaddress.ip_address(b)
    if int(ia) > int(ib):
        ia, ib = ib, ia
    n = int(ib) - int(ia) + 1
    if n > 513:
        return []
    return [str(ipaddress.ip_address(x)) for x in range(int(ia), int(ib) + 1)]


def _expand_last_octet(prefix: str, lo: int, hi: int) -> list[str]:
    """Last-octet sweep ``prefix+o``; empty if span exceeds 512 addresses."""
    lo, hi = min(lo, hi), max(lo, hi)
    if hi - lo > 512:
        return []
    return [f"{prefix}{o}" for o in range(lo, hi + 1)]


_AUD_IP_TOKEN = re.compile(r"(?i)^IP_((?:\d{1,3}\.){3}\d{1,3})$")
_AUD_HOST_TOKEN = re.compile(r"(?i)^Host_((?:\d{1,3}\.){3}\d{1,3})$")
_AUD_NET_SLASH = re.compile(r"(?i)^net_((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})$")
_AUD_NET_UNDERSCORE = re.compile(r"(?i)^net_((?:\d{1,3}\.){3}\d{1,3})_(\d{1,2})$")
_AUD_RANGE_TOKEN = re.compile(r"(?i)^Range_((?:\d{1,3}\.){3})(\d+)-(\d+)$")
_AUD_SVC_TOKEN = re.compile(r"(?i)^(TCP|UDP)_(\d+)(?:-(\d+))?$")


def expand_audit_network_token(token: str, _depth: int = 0) -> list[str]:
    """Expand one audit-export address token to host/network strings, or [] if unknown / too large."""
    t = token.strip()
    if not t or _depth > 1:
        return []
    mf = _AUD_IPV4_DASH_RANGE.fullmatch(t)
    if mf:
        return _expand_two_ipv4(mf.group(1), mf.group(2))
    ml = _AUD_LAST_OCTET_RANGE.fullmatch(t)
    if ml:
        return _expand_last_octet(ml.group(1), int(ml.group(2)), int(ml.group(3)))
    m = _AUD_IP_TOKEN.fullmatch(t) or _AUD_HOST_TOKEN.fullmatch(t)
    if m:
        return [m.group(1)]
    m = _AUD_NET_SLASH.fullmatch(t)
    if m:
        return [f"{m.group(1)}/{m.group(2)}"]
    m = _AUD_NET_UNDERSCORE.fullmatch(t)
    if m:
        return [f"{m.group(1)}/{m.group(2)}"]
    m = _AUD_RANGE_TOKEN.fullmatch(t)
    if m:
        return _expand_last_octet(m.group(1), int(m.group(2)), int(m.group(3)))
    try:
        net = ipaddress.ip_network(t, strict=False)
        return [str(net)]
    except ValueError:
        try:
            ip = ipaddress.ip_address(t)
            return [str(ipaddress.ip_network(f"{ip}/32", strict=False))]
        except ValueError:
            pass
    mpre = _P_STRIP.fullmatch(t)
    if mpre and _depth == 0:
        return expand_audit_network_token(mpre.group(2).strip(), _depth + 1)
    return []


def parse_audit_report_endpoint(text: str) -> AddrLiteral | AddrRef | AddrCompound | None:
    return parse_endpoint_text(text.replace("\n", " "))


def parse_audit_report_service(
    text: str,
) -> ServiceLiteral | ServiceRef | ServiceBundle | ServiceCompound | None:
    raw = text.strip()
    if not raw:
        return None
    tokens = [t for t in re.split(r"\s+", raw) if t]
    by_proto: dict[str, list[PortInterval]] = {}
    objects: list[str] = []
    for tok in tokens:
        m = _AUD_SVC_TOKEN.fullmatch(tok)
        if not m:
            if re.fullmatch(r"[A-Za-z0-9_.\-]+", tok):
                objects.append(tok)
                continue
            if not by_proto and not objects:
                loose = parse_loose_service_field(raw)
                if loose is not None:
                    return loose
                return parse_service_text(raw) or ServiceRef(raw)
            loose = parse_loose_service_field(raw)
            if loose is not None:
                return loose
            return ServiceRef(raw)
        proto = m.group(1).lower()
        lo = int(m.group(2))
        hi = int(m.group(3)) if m.group(3) else lo
        by_proto.setdefault(proto, []).append(PortInterval(min(lo, hi), max(lo, hi)))
    lit_parts: list[ServiceLiteral] = []
    for proto in sorted(by_proto.keys()):
        merged = merge_port_intervals(by_proto[proto])
        lit_parts.append(ServiceLiteral(proto, merged))
    lit_tuple = tuple(lit_parts)
    obj_tuple = tuple(objects)
    if lit_tuple and obj_tuple:
        return ServiceCompound(lit_tuple, obj_tuple)
    if lit_tuple:
        if len(lit_tuple) == 1:
            return lit_tuple[0]
        return ServiceBundle(lit_tuple)
    if obj_tuple:
        if len(obj_tuple) == 1:
            return ServiceRef(obj_tuple[0])
        return ServiceCompound((), obj_tuple)
    return None


def normalize_change_kind(text: str) -> str | None:
    t = unicode_fold_punct(text).casefold()
    if not t:
        return None
    aliases = {
        "add": "add",
        "new": "add",
        "create": "add",
        "modify": "modify",
        "change": "modify",
        "update": "modify",
        "remove": "remove",
        "delete": "remove",
        "disabled": "disabled",
        "disable": "disabled",
    }
    return aliases.get(t, t if t in {"add", "modify", "remove", "disabled"} else None)
