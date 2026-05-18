# fwintegrity

Compare **policy audit exports** (tabular) with **change tickets** (CSV or dict rows). Normalize addresses, services, and change kinds, then **match** rows bidirectionally or build **atomic triple** indexes for coverage checks.

## Install

```bash
pip install fwintegrity
```

## Quick use

```python
from fwintegrity import (
    AUDIT_EXPORT_DEFAULT_MAPPING,
    TICKET_CSV_DEFAULT_MAPPING,
    build_ticket_triple_index,
    from_csv_text,
    link_audit_to_ticket_requests,
    load_change_rows,
)

audit_rows = load_change_rows(from_csv_text(audit_csv), AUDIT_EXPORT_DEFAULT_MAPPING)
ticket_rows = load_change_rows(from_csv_text(ticket_csv), TICKET_CSV_DEFAULT_MAPPING)
links = link_audit_to_ticket_requests(audit_rows, ticket_rows)
idx = build_ticket_triple_index(ticket_rows)
```

Legacy string audit CSV (wide `_CANON` headers) still works: `link_audit_to_ticket_requests(audit_csv_text, ticket_csv_text)`.

See `scripts/sample_demo.py` for a minimal example.

**在线演示（GitHub Pages）**：在仓库 Settings → Pages 选择 **Deploy from branch**、目录 **`/docs`**（或由 Actions 部署 `github-pages` 环境）。访问 `https://<user>.github.io/fwintegrity/` 粘贴 CSV 在线比对（浏览器内 Pyodide 加载 PyPI 包）。

## Documentation

- **[Customization guide](docs/CUSTOMIZATION.md)** — how to adapt parsers, column maps, ignore lists, and matching rules to your organization’s formats (vendor-neutral extension points).

## Features (summary)

- **Endpoints**: IPv4 literals/CIDR, prefixed audit-export tokens (`IP_`, `Host_`, `net_`, `Range_`, …), optional **object/group** names; mixed cells become `AddrCompound`.
- **Services**: `TCP_443`-style audit tokens, loose ticket strings (`TCP 80 UDP 53`), optional **service object** names → `ServiceCompound`.
- **Matching**: bidirectional containment on source, destination, and service (`change_match`, `compare_changes`).
- **Triples**: `TicketTripleIndex` / `audit_triples_all_in_index` for `(src_atom, dst_atom, svc_atom)` style checks.
- **Loading**: declare columns with `ChangeRowMapping`, then `from_csv_text` / `from_csv_path` / `from_excel_path` / `from_dict_rows` / `from_package_resource` + `load_change_rows` (see `table_load.py`).

## Requirements

Python 3.10+

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
```

## Build and publish to PyPI

1. [Create a PyPI account](https://pypi.org/account/register/) and [API token](https://pypi.org/manage/account/token/).
2. Bump `version` in `pyproject.toml` and `src/fwintegrity/__init__.py` (`__version__`).
3. Build and upload:

```bash
pip install build twine
python -m build
twine check dist/*
twine upload dist/*
```

Use **TestPyPI** first if you prefer: `twine upload --repository testpypi dist/*`

## Customization (PyPI / offline)

The wheel ships the Python package only. **Vendor-specific behavior** is adjusted by editing or wrapping:

| Area | Location |
|------|----------|
| Column mapping + unified load | `table_load.ChangeRowMapping`, `load_change_rows`, `from_*` sources; optional `mapping=` on `load_audit_table` / `load_ticket_table` |
| Audit CSV header → keys (legacy wide export) | `audit_report._CANON` |
| Ticket id columns | `ticket._TICKET_NUMBER_KEYS` |
| Address & service parsing | `normalize.parse_*`, `expand_audit_network_token`, `_iter_loose_tcp_udp_segments` |
| Change-kind compatibility (audit vs ticket) | `compare.DEFAULT_AUDIT_TO_TICKET_KINDS` or pass `matrix=` |
| Ignored services (ICMP, etc.) | `ignore_lists.DEFAULT_IGNORED_SERVICE_NAMES`, `merged_ignored_service_names` |
| Triple key strings | `triple_index.endpoint_atom_keys`, `service_atom_keys` |

Clone the repository for the full walkthrough: **`docs/CUSTOMIZATION.md`** (Chinese, file paths and hooks).

## License

MIT — see [LICENSE](LICENSE).
