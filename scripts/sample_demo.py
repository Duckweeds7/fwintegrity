from __future__ import annotations

import json

from fwintegrity import (
    AUDIT_EXPORT_DEFAULT_MAPPING,
    TICKET_CSV_DEFAULT_MAPPING,
    audit_rows_to_changes,
    audit_triples_all_in_index,
    build_ticket_triple_index,
    from_csv_text,
    link_audit_to_ticket_requests,
    load_change_rows,
    merged_ignored_service_names,
)

AUDIT = """Hostname,Change Type,Policy,Number,Name,Scope,Status,Source Zone,Source,User,Destination Zone,Destination,Application,Service,URL Category,Action,Security Profile,TCP Falgs,Schedule Object,Logging,Vendor Tag
fw-core,Add,POL-EDGE,10,r1,,ok,,IP_10.10.10.10 IP_10.10.10.11,,,Host_10.20.20.20,,TCP_443 TCP_80,,allow,,,,,
fw-core,Add,POL-ICMP,11,r2,,ok,,192.168.0.1,,,192.168.0.2,,ICMP/8,,allow,,,,,
fw-dmz,Add,POL-DMZ,20,r3,,ok,,172.16.5.1,,,172.16.6.10,,UDP_53,,allow,,,,,
fw-core,Add,POL-ORPH,99,rx,,ok,,10.255.1.1,,,10.255.2.2,,tcp/9999,,allow,,,,,
"""

TICKETS = """Ticket Number,INF Number,Action,Source IP Address,Destination IP Address,Service Port
CHG-100,INF-A001,Add,"10.10.10.10, 10.10.10.11",10.20.20.20,TCP 443 TCP 80
CHG-100,INF-A002,Add,192.168.0.1,192.168.0.2,ICMP/8
CHG-200,INF-B001,Add,172.16.5.1,172.16.6.10,UDP 53
CHG-200,INF-B001,Add,172.16.5.2,172.16.6.11,udp/53
"""

if __name__ == "__main__":
    ign = merged_ignored_service_names(None)
    ticket_rows = load_change_rows(from_csv_text(TICKETS), TICKET_CSV_DEFAULT_MAPPING)
    audit_rows = load_change_rows(from_csv_text(AUDIT), AUDIT_EXPORT_DEFAULT_MAPPING)
    idx = build_ticket_triple_index(ticket_rows, ignored_services=ign)

    out: dict = {"link": [], "triple_check": []}

    links = link_audit_to_ticket_requests(audit_rows, ticket_rows, ignored_services=ign)
    for L in links:
        out["link"].append(
            {
                "audit_row": L.audit_row_index,
                "change": L.audit.change.value if L.audit else None,
                "ticket_numbers": list(L.ticket_numbers),
                "inf_numbers": list(L.inf_numbers),
                "parse_msgs": list(L.audit_parse_messages),
            }
        )

    audits = audit_rows_to_changes(audit_rows)
    for i, ach in enumerate(audits):
        ok, miss = audit_triples_all_in_index(ach, idx, ignored_services=ign)
        out["triple_check"].append(
            {"audit_row_norm_index": i, "all_triples_in_index": ok, "missing_count": len(miss)}
        )

    print(json.dumps(out, indent=2, ensure_ascii=False))
