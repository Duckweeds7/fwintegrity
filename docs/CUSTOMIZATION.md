# 定制指南（按公司自己的标准改）

本库把「读表 → 规范化 → 比对」拆成几块。**改自己公司的列名、解析规则、忽略策略、变更类型映射**时，优先改下表中的位置；不必 fork 全库时，也可以在业务代码里包一层适配器，把你们的行 `dict` 转成当前 API 能吃的字段名再调用。

## 1. 调用侧列映射 + 统一加载（推荐）

文件：`src/fwintegrity/table_load.py`

- **`ChangeRowMapping`**：在业务入口声明列标题（表头原文即可）对应 **`change_kind` / `source` / `destination` / `service`**；工单还可选 **`ticket_number` / `inf_number`**。
- **预设**：`AUDIT_EXPORT_DEFAULT_MAPPING`、`TICKET_CSV_DEFAULT_MAPPING`（与内置默认列名一致）。
- **数据源（显式）**：`from_csv_text`、`from_csv_path`、`from_excel_path`（需安装 `fwintegrity[excel]` 或 `openpyxl`）、`from_dict_rows`、`from_package_resource`（`importlib.resources`，适合 wheel 内嵌 CSV）。
- **`load_change_rows(source, mapping)`** → 每行只保留规范键：`change_type`、`source`、`destination`、`service`（及票号键），再交给 `link_audit_to_ticket_requests`、`audit_row_to_normalized` 等。
- **`load_audit_table` / `load_ticket_table`**：支持 `Path`；传入 **`mapping=`** 时用上述语义读 CSV，不再依赖审计专用的 `_CANON` 宽表解析（仍兼容不传 `mapping` 的旧用法）。

## 2. 审计导出（Audit）列名 — 旧版宽表

文件：`src/fwintegrity/audit_report.py`

- 表头会先 **slugify**（小写、空格变下划线、去掉非字母数字下划线）。
- **`_CANON`**：slug → 内部固定键。内部行里用的是 `change_type`、`source`、`destination`、`service` 等。
- **做法**：在 `_CANON` 里增加你们导出里出现的表头 slug；或在上游把 CSV 列名改成与现有 canonical 一致；**更推荐改用第 1 节的 `load_change_rows` + 自建 `ChangeRowMapping`**。

解析入口：`audit_row_to_normalized` → `parse_audit_report_endpoint` / `parse_audit_report_service`。

## 3. 工单（Ticket）列名与票号字段

文件：`src/fwintegrity/ticket.py`

- **`row_to_normalized_change`** 在 slug 化后的行上读取（**规范键优先，旧键兼容**）：
  - 变更类型：`change_type`，若无则 `action`
  - 源/目的：`source` / `destination`，若无则 `source_ip_address` / `destination_ip_address`
  - 服务：`service`，若无则 `service_port`
- **`_TICKET_NUMBER_KEYS`**：从这些键里找工单号（任一非空即用）；规范键 **`ticket_number`** 已包含在内。
- **`inf_number_from_row`**：`inf_number` / `infnumber` / `item` 等。

**做法**：扩展 `_TICKET_NUMBER_KEYS`；或使用 **`TICKET_CSV_DEFAULT_MAPPING` + `load_change_rows`** 在入口统一列名。

## 4. 地址 / 服务解析（最常被各厂商差异打中）

文件：`src/fwintegrity/normalize.py`

| 能力 | 函数 / 常量 | 说明 |
|------|-------------|------|
| 工单侧地址 | `parse_endpoint_text` | 逗号/空白分词、IP/CIDR、审计导出前缀 token 展开、其余进 object |
| 审计侧地址 | `parse_audit_report_endpoint` | 目前等同 `parse_endpoint_text`（换行转空格） |
| 工单侧服务 | `parse_ticket_service_field` | 先 loose TCP/UDP 扫描，再 `parse_service_text` |
| Loose 服务串 | `parse_loose_service_field`、`_iter_loose_tcp_udp_segments` | 按单词 `TCP`/`UDP` 定位，端口只读 `_PORT_CHARS` 内字符，中间文字进 object |
| 审计导出服务 token | `parse_audit_report_service`、`_AUD_SVC_TOKEN` 等 | `TCP_443` 与标识符 object 混排 |
| IP 范围展开上限 | `_expand_two_ipv4` / `_expand_last_octet` 里 **513 / 512** | 防止爆炸展开；可按内网规模调大（注意性能） |
| 审计导出地址 token | `expand_audit_network_token`、`_AUD_*` 正则 | 加前缀/新格式时改这里 |

**做法**：在你们工程里 `import fwintegrity.normalize as n` 后 **猴子补丁** 替换某个 `parse_*`（适合试点）；长期维护建议 fork 或 vendoring 后改上述函数。

## 5. 变更类型（Change kind）与工单动作对齐

文件：

- `src/fwintegrity/normalize.py` → **`normalize_change_kind`**（别名表 + 合法枚举）
- `src/fwintegrity/compare.py` → **`DEFAULT_AUDIT_TO_TICKET_KINDS`**

例如「审计里是 modify，工单里是 disabled」是否算匹配，由 **`DEFAULT_AUDIT_TO_TICKET_KINDS`** 决定。调用 `change_match` / `link_audit_to_ticket_requests` / `compare_changes` 时可传入自定义 **`matrix`** 覆盖默认表。

## 6. 服务忽略（ICMP 等不参与比对 / 不出 triple）

文件：`src/fwintegrity/ignore_lists.py`

- **`DEFAULT_IGNORED_SERVICE_NAMES`**：按名字规范化后匹配。
- **`service_spec_ignored`**：对 `ServiceLiteral` / `ServiceRef` / `ServiceBundle` / `ServiceCompound` 的规则。

比对时传 **`merged_ignored_service_names(frozenset({...}))`** 给 `change_match` 等，可叠加你们自己的忽略名。

## 7. 比对语义（端点 / 服务覆盖）

文件：`src/fwintegrity/compare.py`

- **`endpoint_covers`**：`AddrLiteral` / `AddrRef` / `AddrCompound` 统一成 compound 后做子集判断。
- **`service_covers`**：literal/bundle 用 `_service_covers_simple`；compound 再叠 object 名子集。

若你们需要「同一 object 名多种写法等价」等，可在规范化前做字符串映射，或改 **`_compound_covers` / `_compound_service_covers`** 里的比较逻辑。

## 8. Triple 索引键格式

文件：`src/fwintegrity/triple_index.py`

- 端点：`i:<cidr>`、`g:<object casefold>`
- 服务：`s:<proto>:<port>`、`sr:g:<name>`

与外部 CMDB/对象库对齐时，可约定 object 名预处理后再进 `parse_*`，或 fork 后改 **`endpoint_atom_keys` / `service_atom_keys`** 的前缀与拼接规则。

## 9. 已规范化数据直接接入

若你们已有自己的解析器，只要构造 **`NormalizedChange`**（`models.py`）即可复用 **`change_match`**、**`compare_changes`**、**`TicketTripleIndex`**，完全绕过 CSV 与 `parse_*`。

---

**发布 PyPI**：见仓库根目录 `README.md` 的 *Build and publish*；版本号需同时改 `pyproject.toml` 与 `src/fwintegrity/__init__.py` 中的 `__version__`。
