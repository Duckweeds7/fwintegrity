from fwintegrity.audit_report import audit_row_to_normalized, parse_audit_report_text
from fwintegrity.table_load import (
    AUDIT_EXPORT_DEFAULT_MAPPING,
    TICKET_CSV_DEFAULT_MAPPING,
    from_csv_text,
    from_dict_rows,
    load_change_rows,
)
from fwintegrity.ticket import parse_ticket_csv_text, row_to_normalized_change


def test_ticket_csv_mapping_matches_legacy_parse():
    csv = """Ticket Number,INF Number,Action,Source IP Address,Destination IP Address,Service Port
T1,I1,add,10.0.0.1,10.0.0.2,tcp/443
"""
    legacy = parse_ticket_csv_text(csv)
    mapped = load_change_rows(from_csv_text(csv), TICKET_CSV_DEFAULT_MAPPING)
    assert len(legacy) == len(mapped) == 1
    a, _ = row_to_normalized_change(legacy[0])
    b, _ = row_to_normalized_change(mapped[0])
    assert a is not None and b is not None
    assert a.change == b.change
    assert a.source == b.source and a.destination == b.destination and a.service == b.service


def test_audit_csv_mapping_matches_legacy_row():
    csv = """Hostname,Change Type,Policy,Number,Name,Scope,Status,Source Zone,Source,User,Destination Zone,Destination,Application,Service,URL Category,Action,Security Profile,TCP Falgs,Schedule Object,Logging,Vendor Tag
fw1,Add,POL,1,n,,ok,,10.1.1.1,,,10.2.2.2,,TCP_443,,allow,,,,,
"""
    legacy_rows = parse_audit_report_text(csv)
    mapped_rows = load_change_rows(from_csv_text(csv), AUDIT_EXPORT_DEFAULT_MAPPING)
    assert len(legacy_rows) == len(mapped_rows) == 1
    la, _ = audit_row_to_normalized(legacy_rows[0])
    ma, _ = audit_row_to_normalized(mapped_rows[0])
    assert la is not None and ma is not None
    assert la.change == ma.change
    assert la.source == ma.source and la.destination == ma.destination and la.service == ma.service


def test_from_dict_rows_with_mapping():
    rows = [
        {
            "Action": "add",
            "Source IP Address": "10.0.0.1",
            "Destination IP Address": "10.0.0.2",
            "Service Port": "tcp/443",
            "Ticket Number": "X1",
            "INF Number": "Y1",
        }
    ]
    out = load_change_rows(from_dict_rows(rows), TICKET_CSV_DEFAULT_MAPPING)
    assert out[0]["ticket_number"] == "X1"
    assert out[0]["change_type"] == "add"
