from fwintegrity.models import AddrLiteral
from fwintegrity.triple_index import endpoint_atom_keys


def test_adjacent_hosts_merge_to_one_range_key():
    keys = endpoint_atom_keys(AddrLiteral(("10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32")))
    assert keys == ["i:10.0.0.1-10.0.0.3"]


def test_single_host_key_without_cidr():
    keys = endpoint_atom_keys(AddrLiteral(("10.0.0.5/32",)))
    assert keys == ["i:10.0.0.5"]


def test_non_adjacent_hosts_stay_separate_ranges():
    keys = endpoint_atom_keys(AddrLiteral(("10.0.0.1/32", "10.0.0.5/32")))
    assert sorted(keys) == ["i:10.0.0.1", "i:10.0.0.5"]


def test_cidr_becomes_inclusive_range_not_subnet_key():
    keys = endpoint_atom_keys(AddrLiteral(("10.0.0.0/30",)))
    assert keys == ["i:10.0.0.0-10.0.0.3"]
