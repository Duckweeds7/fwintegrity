from fwintegrity.compare import change_match
from fwintegrity.models import (
    AddrLiteral,
    ChangeKind,
    NormalizedChange,
    PortInterval,
    ServiceLiteral,
)


def test_match_audit_subset_of_ticket_addrs_and_service():
    audit = NormalizedChange(
        ChangeKind.ADD,
        AddrLiteral(("10.0.0.1/32",)),
        AddrLiteral(("10.0.0.2/32",)),
        ServiceLiteral("tcp", (PortInterval(443, 443),)),
    )
    ticket = NormalizedChange(
        ChangeKind.ADD,
        AddrLiteral(("10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32")),
        AddrLiteral(("10.0.0.2/32",)),
        ServiceLiteral("tcp", (PortInterval(80, 80), PortInterval(443, 443))),
    )
    assert change_match(audit, ticket)


def test_match_ticket_subset_of_audit_still_works():
    audit = NormalizedChange(
        ChangeKind.ADD,
        AddrLiteral(("10.0.0.1/32", "10.0.0.2/32")),
        AddrLiteral(("10.0.0.2/32",)),
        ServiceLiteral("tcp", (PortInterval(80, 80), PortInterval(443, 443))),
    )
    ticket = NormalizedChange(
        ChangeKind.ADD,
        AddrLiteral(("10.0.0.1/32",)),
        AddrLiteral(("10.0.0.2/32",)),
        ServiceLiteral("tcp", (PortInterval(443, 443),)),
    )
    assert change_match(audit, ticket)


def test_no_match_when_neither_direction_covers():
    audit = NormalizedChange(
        ChangeKind.ADD,
        AddrLiteral(("10.0.0.1/32",)),
        AddrLiteral(("10.0.0.2/32",)),
        ServiceLiteral("tcp", (PortInterval(443, 443),)),
    )
    ticket = NormalizedChange(
        ChangeKind.ADD,
        AddrLiteral(("10.0.0.9/32",)),
        AddrLiteral(("10.0.0.2/32",)),
        ServiceLiteral("tcp", (PortInterval(443, 443),)),
    )
    assert not change_match(audit, ticket)
