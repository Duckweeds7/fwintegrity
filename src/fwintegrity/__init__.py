"""Normalize firewall audit rows and change tickets, then match or triple-index them.

Extension points for vendor-specific formats are documented in ``docs/CUSTOMIZATION.md``.
"""

from .audit_report import (
    audit_row_to_normalized,
    iter_audit_rows_normalized,
    parse_audit_report_text,
    rows_to_normalized_changes as audit_rows_to_changes,
)
from .compare import AuditRuleRequestLink, CompareResult, compare_changes, link_audit_to_ticket_requests
from .inputs import load_audit_table, load_ticket_table
from .models import (
    AddrCompound,
    AddrLiteral,
    AddrRef,
    ChangeKind,
    NormalizedChange,
    PortInterval,
    ServiceBundle,
    ServiceCompound,
    ServiceLiteral,
    ServiceRef,
)
from .ignore_lists import (
    DEFAULT_IGNORED_SERVICE_NAMES,
    merged_ignored_service_names,
    service_name_ignored,
    service_spec_ignored,
)
from .normalize import (
    parse_audit_report_endpoint,
    parse_audit_report_service,
    parse_loose_service_field,
    parse_ticket_service_field,
)
from .ticket import (
    inf_number_from_row,
    iter_ticket_rows_normalized,
    parse_ticket_csv_text,
    row_to_normalized_change,
    rows_to_normalized_changes,
    ticket_number_from_row,
    ticket_request_id,
)
from .triple_index import (
    TicketTripleIndex,
    TripleHit,
    audit_triples_all_in_index,
    build_ticket_triple_index,
    iter_change_triples,
)

__all__ = [
    "__version__",
    "AddrCompound",
    "AddrLiteral",
    "AddrRef",
    "AuditRuleRequestLink",
    "ChangeKind",
    "CompareResult",
    "DEFAULT_IGNORED_SERVICE_NAMES",
    "NormalizedChange",
    "PortInterval",
    "ServiceCompound",
    "ServiceBundle",
    "ServiceLiteral",
    "ServiceRef",
    "TicketTripleIndex",
    "TripleHit",
    "audit_row_to_normalized",
    "audit_rows_to_changes",
    "audit_triples_all_in_index",
    "build_ticket_triple_index",
    "compare_changes",
    "iter_audit_rows_normalized",
    "iter_change_triples",
    "iter_ticket_rows_normalized",
    "inf_number_from_row",
    "link_audit_to_ticket_requests",
    "load_audit_table",
    "load_ticket_table",
    "merged_ignored_service_names",
    "parse_audit_report_endpoint",
    "parse_audit_report_service",
    "parse_audit_report_text",
    "parse_loose_service_field",
    "parse_ticket_csv_text",
    "parse_ticket_service_field",
    "row_to_normalized_change",
    "rows_to_normalized_changes",
    "service_name_ignored",
    "service_spec_ignored",
    "ticket_number_from_row",
    "ticket_request_id",
]

__version__ = "0.2.0"
