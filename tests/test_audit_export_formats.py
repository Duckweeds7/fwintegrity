from fwintegrity import link_audit_to_ticket_requests
from fwintegrity.models import ServiceBundle
from fwintegrity.normalize import (
    parse_audit_report_endpoint,
    parse_audit_report_service,
)


def test_audit_export_ip_prefix_tokens():
    e = parse_audit_report_endpoint("IP_10.6.26.13 IP_10.6.26.14")
    assert e is not None
    assert hasattr(e, "networks")


def test_audit_export_range_and_net_tokens():
    e = parse_audit_report_endpoint("Range_10.72.82.4-5 net_10.164.130.0/24")
    assert e is not None


def test_audit_export_net_underscore_mask():
    e = parse_audit_report_endpoint("net_10.1.154.0_24")
    assert e is not None


def test_audit_export_tcp_udp_bundle():
    s = parse_audit_report_service("TCP_53 UDP_53")
    assert isinstance(s, ServiceBundle)
    assert len(s.parts) == 2


def test_link_audit_multi_ip_ticket_single():
    audit_csv = """Hostname,Change Type,Policy,Number,Name,Scope,Status,Source Zone,Source,User,Destination Zone,Destination,Application,Service,URL Category,Action,Security Profile,TCP Falgs,Schedule Object,Logging,Vendor Tag
fw1,add,pol1,1,r1,,ok,,IP_10.6.26.13 IP_10.6.26.14,,,Host_10.164.141.36,,TCP_443,,allow,,,,,
"""
    ticket_csv = """Ticket Number,INF Number,Action,Source IP Address,Destination IP Address,Service Port
CRQ-1,INF-9,add,10.6.26.14,10.164.141.36,tcp/443
"""
    links = link_audit_to_ticket_requests(audit_csv, ticket_csv)
    assert links[0].inf_numbers == ("INF-9",)


def test_audit_export_named_object_ref():
    e = parse_audit_report_endpoint("HKEX_OA_Users")
    assert hasattr(e, "name")
