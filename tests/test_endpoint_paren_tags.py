from fwintegrity.models import AddrLiteral
from fwintegrity.normalize import parse_endpoint_text


def test_ip_with_glued_paren_tag():
    e = parse_endpoint_text("10.0.0.1(OA) 10.0.0.2(VIP)")
    assert isinstance(e, AddrLiteral)
    assert "10.0.0.1/32" in e.networks
    assert "10.0.0.2/32" in e.networks


def test_single_ip_glued_tag():
    e = parse_endpoint_text("192.168.1.10(VIP)")
    assert isinstance(e, AddrLiteral)
    assert e.networks == ("192.168.1.10/32",)


def test_spaced_paren_still_parses_ip():
    e = parse_endpoint_text("10.0.0.1 (OA)")
    assert isinstance(e, AddrLiteral)
    assert "10.0.0.1/32" in e.networks


def test_cidr_with_glued_tag():
    e = parse_endpoint_text("10.0.0.0/24(OA)")
    assert isinstance(e, AddrLiteral)
    assert "10.0.0.0/24" in e.networks
