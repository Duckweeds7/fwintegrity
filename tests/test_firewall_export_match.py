from fwintegrity import (
    AUDIT_EXPORT_DEFAULT_MAPPING,
    TICKET_FIREWALL_EXPORT_MAPPING,
    from_csv_text,
    link_audit_to_ticket_requests,
    load_change_rows,
)
from fwintegrity.normalize import parse_ticket_service_field
from fwintegrity.ticket import row_to_normalized_change


def test_ticket_service_comma_and_tcp_underscore_tokens():
    s = parse_ticket_service_field("TCP_139, TCP_445, TCP_1435, UDP_137-138")
    assert s is not None
    assert hasattr(s, "parts") or (hasattr(s, "proto") and s.proto == "tcp")


def test_firewall_export_row_without_action_defaults_add():
    row = {
        "source_ip_address": "WOAFHK-D1076.OA.CORP.HKEX",
        "destination_ip_address": "10.244.192.70",
        "service_port": "TCP_139, TCP_445, TCP_1435, UDP_137-138",
    }
    ch, iss = row_to_normalized_change(row)
    assert ch is not None
    assert ch.change.value == "add"
    assert "default_action_add" in [x.message for x in iss]


def test_link_firewall_export_style_rows():
    audit_csv = """Hostname,Change Type,Source,Destination,Service
fw1,Add,WOAFHK-D1076.OA.CORP.HKEX,IP_10.244.192.70,TCP_139 TCP_1435 TCP_445 UDP_137-138
"""
    ticket_csv = """Source IP Address,Destination IP Address,Service Port
WOAFHK-D1076.OA.CORP.HKEX,10.244.192.70,"TCP_139, TCP_445, TCP_1435, UDP_137-138"
"""
    audit_rows = load_change_rows(from_csv_text(audit_csv), AUDIT_EXPORT_DEFAULT_MAPPING)
    ticket_rows = load_change_rows(from_csv_text(ticket_csv), TICKET_FIREWALL_EXPORT_MAPPING)
    links = link_audit_to_ticket_requests(audit_rows, ticket_rows)
    assert links[0].audit is not None
    assert links[0].audit is not None
    assert len(links[0].matched_ticket_row_indices) >= 1 or links[0].ticket_numbers
