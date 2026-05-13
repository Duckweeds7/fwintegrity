from fwintegrity.compare import change_match
from fwintegrity.ignore_lists import service_spec_ignored
from fwintegrity.models import AddrLiteral, ChangeKind, NormalizedChange, PortInterval, ServiceLiteral, ServiceRef
from fwintegrity.normalize import expand_audit_network_token, parse_endpoint_text


def test_expand_plain_last_octet():
    xs = expand_audit_network_token("192.168.1.1-10")
    assert len(xs) == 10


def test_expand_two_full_ips():
    xs = expand_audit_network_token("192.168.1.1-192.168.1.3")
    assert len(xs) == 3


def test_expand_ip_range_prefix():
    xs = expand_audit_network_token("Ip_Range_10.0.0.1-3")
    assert len(xs) == 3


def test_parse_endpoint_mixed_case_prefix():
    e = parse_endpoint_text("hOST_10.0.0.5")
    assert isinstance(e, AddrLiteral)


def test_service_spec_ignored_icmp():
    assert service_spec_ignored(ServiceRef("ICMP/8"))
    assert service_spec_ignored(ServiceRef("ping"))


def test_change_match_skips_service_when_icmp():
    a = NormalizedChange(
        ChangeKind.ADD,
        AddrLiteral(("10.0.0.1/32",)),
        AddrLiteral(("10.0.0.2/32",)),
        ServiceRef("ICMP/8"),
    )
    t = NormalizedChange(
        ChangeKind.ADD,
        AddrLiteral(("10.0.0.1/32",)),
        AddrLiteral(("10.0.0.2/32",)),
        ServiceLiteral("tcp", (PortInterval(443, 443),)),
    )
    assert change_match(a, t)


def test_normalize_change_kind_title_case():
    from fwintegrity.normalize import normalize_change_kind

    assert normalize_change_kind("Add") == "add"
    assert normalize_change_kind("Modify") == "modify"
    assert normalize_change_kind("Remove") == "remove"
    assert normalize_change_kind("Disabled") == "disabled"
