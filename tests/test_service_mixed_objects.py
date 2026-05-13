from fwintegrity.compare import change_match, service_covers
from fwintegrity.models import (
    AddrLiteral,
    ChangeKind,
    NormalizedChange,
    ServiceCompound,
)
from fwintegrity.normalize import parse_audit_report_service, parse_loose_service_field
from fwintegrity.triple_index import service_atom_keys


def test_loose_literals_plus_object_gap():
    s = parse_loose_service_field("TCP 80 APP_Group UDP 53")
    assert isinstance(s, ServiceCompound)
    keys = service_atom_keys(s)
    assert sum(1 for k in keys if k.startswith("s:")) == 2
    assert sum(1 for k in keys if k.startswith("sr:g:")) == 1


def test_audit_export_svc_tokens_plus_object():
    s = parse_audit_report_service("TCP_443 Web_Svc")
    assert isinstance(s, ServiceCompound)
    assert len(s.objects) == 1


def test_service_covers_compound_subset():
    outer = parse_loose_service_field("TCP 80 S1")
    inner = parse_loose_service_field("TCP 80 TCP 443 S1")
    assert isinstance(outer, ServiceCompound) and isinstance(inner, ServiceCompound)
    assert not service_covers(outer, inner)
    assert service_covers(inner, outer)


def test_change_match_compound_service():
    svc = parse_loose_service_field("TCP 443 SvcObj")
    a = NormalizedChange(
        ChangeKind.ADD,
        AddrLiteral(("10.0.0.1/32",)),
        AddrLiteral(("10.0.0.2/32",)),
        svc,
    )
    t = NormalizedChange(
        ChangeKind.ADD,
        AddrLiteral(("10.0.0.1/32",)),
        AddrLiteral(("10.0.0.2/32",)),
        svc,
    )
    assert change_match(a, t)


def test_objects_only_multiple_is_compound():
    s = parse_audit_report_service("A B")
    assert isinstance(s, ServiceCompound)
    assert not s.literals
    assert len(s.objects) == 2
