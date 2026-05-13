from fwintegrity.compare import change_match
from fwintegrity.models import AddrCompound, AddrLiteral, ChangeKind, NormalizedChange, PortInterval, ServiceLiteral
from fwintegrity.normalize import parse_endpoint_text
from fwintegrity.triple_index import endpoint_atom_keys


def test_mixed_ip_and_object_middle_is_compound_with_atoms():
    e = parse_endpoint_text("IP_10.1.1.1 DMZ_Web IP_10.1.1.2")
    assert isinstance(e, AddrCompound)
    keys = endpoint_atom_keys(e)
    assert len(keys) == 3
    assert sum(1 for k in keys if k.startswith("i:")) == 2
    assert sum(1 for k in keys if k.startswith("g:")) == 1


def test_all_literal_tokens_still_addrliteral():
    e = parse_endpoint_text("IP_10.1.1.1 IP_10.1.1.2")
    assert isinstance(e, AddrLiteral)
    assert len(endpoint_atom_keys(e)) == 2


def test_change_match_object_group_string_equality():
    cell = "10.0.0.1 APP_Group 10.0.0.2"
    a = NormalizedChange(
        ChangeKind.ADD,
        parse_endpoint_text(cell),
        AddrLiteral(("10.20.0.1/32",)),
        ServiceLiteral("tcp", (PortInterval(443, 443),)),
    )
    t = NormalizedChange(
        ChangeKind.ADD,
        parse_endpoint_text(cell),
        AddrLiteral(("10.20.0.1/32",)),
        ServiceLiteral("tcp", (PortInterval(443, 443),)),
    )
    assert change_match(a, t)
