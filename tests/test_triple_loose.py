from fwintegrity import (
    ChangeKind,
    NormalizedChange,
    audit_triples_all_in_index,
    build_ticket_triple_index,
    iter_change_triples,
    parse_loose_service_field,
)
from fwintegrity.models import AddrLiteral, PortInterval, ServiceLiteral
from fwintegrity.triple_index import endpoint_atom_keys, service_atom_keys


def test_parse_loose_mixed_tcp_udp():
    s = parse_loose_service_field("TCP 80 TCP 32 UDP 32,32")
    assert s is not None
    assert hasattr(s, "parts")


def test_ticket_triple_index_lookup():
    csv = """Ticket Number,INF Number,Action,Source IP Address,Destination IP Address,Service Port
T1,INF1,add,10.0.0.1,10.0.0.2,TCP 80 TCP 443
"""
    from fwintegrity import parse_ticket_csv_text

    rows = parse_ticket_csv_text(csv)
    idx = build_ticket_triple_index(rows)
    sk = endpoint_atom_keys(AddrLiteral(("10.0.0.1/32",)))
    dk = endpoint_atom_keys(AddrLiteral(("10.0.0.2/32",)))
    vk = service_atom_keys(ServiceLiteral("tcp", (PortInterval(80, 80),)))
    tri = (sk[0], dk[0], vk[0])
    assert tri in idx
    hits = idx.lookup(tri)
    assert hits and hits[0].inf_number == "INF1"


def test_audit_triples_all_in_index():
    audit = NormalizedChange(
        ChangeKind.ADD,
        AddrLiteral(("10.0.0.1/32",)),
        AddrLiteral(("10.0.0.2/32",)),
        ServiceLiteral("tcp", (PortInterval(80, 80),)),
    )
    csv = """Ticket Number,INF Number,Action,Source IP Address,Destination IP Address,Service Port
T1,INF1,add,10.0.0.1,10.0.0.2,TCP 80
"""
    from fwintegrity import parse_ticket_csv_text

    idx = build_ticket_triple_index(parse_ticket_csv_text(csv))
    ok, miss = audit_triples_all_in_index(audit, idx)
    assert ok and not miss


def test_iter_change_triples_count():
    ch = NormalizedChange(
        ChangeKind.ADD,
        AddrLiteral(("10.0.0.1/32", "10.0.0.2/32")),
        AddrLiteral(("10.0.0.3/32",)),
        ServiceLiteral("tcp", (PortInterval(80, 80), PortInterval(443, 443))),
    )
    tr = list(iter_change_triples(ch, 100))
    assert len(tr) == 2 * 1 * 2
