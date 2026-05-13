from fwintegrity import (
    audit_rows_to_changes,
    compare_changes,
    link_audit_to_ticket_requests,
    load_ticket_table,
    parse_audit_report_text,
    parse_ticket_csv_text,
    ticket_request_id,
)
from fwintegrity.models import PortInterval, ServiceLiteral
from fwintegrity.normalize import merge_port_intervals, parse_port_list_blob, parse_service_text


def test_merge_ports_adjacent():
    iv = merge_port_intervals(parse_port_list_blob("162, 163"))
    assert iv == (PortInterval(162, 163),)


def test_parse_service_tcp_range():
    s = parse_service_text("tcp 162-163")
    assert isinstance(s, ServiceLiteral)
    assert s.proto == "tcp"
    assert s.intervals == (PortInterval(162, 163),)


def test_compare_audit_ticket_csv():
    audit_csv = """Hostname,Change Type,Policy,Number,Name,Scope,Status,Source Zone,Source,User,Destination Zone,Destination,Application,Service,URL Category,Action,Security Profile,TCP Falgs,Schedule Object,Logging,Vendor Tag
fw1,add,pol1,1,r1,,ok,,10.0.0.1,,,10.0.0.2,,tcp/443,,allow,,,,,
"""
    ticket_csv = """Action,Source IP Address,Destination IP Address,Service Port
add,10.0.0.1,10.0.0.2,tcp/443
"""
    ar = parse_audit_report_text(audit_csv)
    tr = parse_ticket_csv_text(ticket_csv)
    a = audit_rows_to_changes(ar)
    from fwintegrity.ticket import rows_to_normalized_changes as ticket_rows

    t = [x[0] for x in ticket_rows(tr)]
    r = compare_changes(a, t)
    assert len(r.matched) == 1
    assert not r.audit_only
    assert not r.ticket_only


def test_modify_matches_disabled():
    audit_csv = """Hostname,Change Type,Policy,Number,Name,Scope,Status,Source Zone,Source,User,Destination Zone,Destination,Application,Service,URL Category,Action,Security Profile,TCP Falgs,Schedule Object,Logging,Vendor Tag
fw1,modify,pol1,1,r1,,ok,,10.1.1.1,,,10.2.2.2,,udp/53,,allow,,,,,
"""
    ticket_csv = """Action,Source IP Address,Destination IP Address,Service Port
disabled,10.1.1.1,10.2.2.2,udp/53
"""
    a = audit_rows_to_changes(parse_audit_report_text(audit_csv))
    from fwintegrity.ticket import rows_to_normalized_changes as ticket_rows

    t = [x[0] for x in ticket_rows(parse_ticket_csv_text(ticket_csv))]
    r = compare_changes(a, t)
    assert len(r.matched) == 1


def test_link_records_inf_number():
    audit_csv = """Hostname,Change Type,Policy,Number,Name,Scope,Status,Source Zone,Source,User,Destination Zone,Destination,Application,Service,URL Category,Action,Security Profile,TCP Falgs,Schedule Object,Logging,Vendor Tag
fw1,add,pol1,1,r1,,ok,,10.0.0.5,,,10.0.0.6,,tcp/443,,allow,,,,,
"""
    ticket_csv = """Ticket Number,INF Number,Action,Source IP Address,Destination IP Address,Service Port
CRQ100,INF-001,add,10.0.0.5,10.0.0.6,tcp/443
"""
    links = link_audit_to_ticket_requests(audit_csv, ticket_csv)
    assert len(links) == 1
    assert links[0].inf_numbers == ("INF-001",)
    assert links[0].ticket_numbers == ("CRQ100",)


def test_load_ticket_multiple_batches():
    t1 = [{"INF Number": "A", "Action": "add", "Source IP Address": "1.1.1.1", "Destination IP Address": "2.2.2.2", "Service Port": "tcp/80"}]
    t2 = [{"INF Number": "B", "Action": "add", "Source IP Address": "3.3.3.3", "Destination IP Address": "4.4.4.4", "Service Port": "tcp/80"}]
    rows = load_ticket_table([t1, t2])
    assert len(rows) == 2
    assert ticket_request_id(rows[0]) == "A"
