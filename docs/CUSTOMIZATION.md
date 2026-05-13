# 定制指南（按公司自己的标准改）

本库把「读表 → 规范化 → 比对」拆成几块。**改自己公司的列名、解析规则、忽略策略、变更类型映射**时，优先改下表中的位置；不必 fork 全库时，也可以在业务代码里包一层适配器，把你们的行 `dict` 转成当前 API 能吃的字段名再调用。

## 1. 审计导出（Audit）列名 → 内部 canonical 名

文件：`src/fwintegrity/audit_report.py`

- 表头会先 **slugify**（小写、空格变下划线、去掉非字母数字下划线）。
- **`_CANON`**：slug → 内部固定键。内部行里用的是 `change_type`、`source`、`destination`、`service` 等。
- **做法**：在 `_CANON` 里增加你们导出里出现的表头 slug；或在上游把 CSV 列名改成与现有 canonical 一致。

解析入口：`audit_row_to_normalized` → `parse_audit_report_endpoint` / `parse_audit_report_service`。

## 2. 工单（Ticket）列名与票号字段

文件：`src/fwintegrity/ticket.py`

- **`row_to_normalized_change`** 读取的键（slug 之后）：
  - `action`
  - `source_ip_address`
  - `destination_ip_address`
  - `service_port`
- **`_TICKET_NUMBER_KEYS`**：从这些键里找工单号（任一非空即用）。
- **`inf_number_from_row`**：`inf_number` / `infnumber` / `item` 等。

**做法**：扩展 `_TICKET_NUMBER_KEYS` 元组；或在上游把你们 CSV 列名 slug 成上述键名；或复制 `row_to_normalized_change` 成你们自己的函数，只改 `r.get(...)` 的键名。

## 3. 地址 / 服务解析（最常被各厂商差异打中）

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

## 4. 变更类型（Change kind）与工单动作对齐

文件：

- `src/fwintegrity/normalize.py` → **`normalize_change_kind`**（别名表 + 合法枚举）
- `src/fwintegrity/compare.py` → **`DEFAULT_AUDIT_TO_TICKET_KINDS`**

例如「审计里是 modify，工单里是 disabled」是否算匹配，由 **`DEFAULT_AUDIT_TO_TICKET_KINDS`** 决定。调用 `change_match` / `link_audit_to_ticket_requests` / `compare_changes` 时可传入自定义 **`matrix`** 覆盖默认表。

## 5. 服务忽略（ICMP 等不参与比对 / 不出 triple）

文件：`src/fwintegrity/ignore_lists.py`

- **`DEFAULT_IGNORED_SERVICE_NAMES`**：按名字规范化后匹配。
- **`service_spec_ignored`**：对 `ServiceLiteral` / `ServiceRef` / `ServiceBundle` / `ServiceCompound` 的规则。

比对时传 **`merged_ignored_service_names(frozenset({...}))`** 给 `change_match` 等，可叠加你们自己的忽略名。

## 6. 比对语义（端点 / 服务覆盖）

文件：`src/fwintegrity/compare.py`

- **`endpoint_covers`**：`AddrLiteral` / `AddrRef` / `AddrCompound` 统一成 compound 后做子集判断。
- **`service_covers`**：literal/bundle 用 `_service_covers_simple`；compound 再叠 object 名子集。

若你们需要「同一 object 名多种写法等价」等，可在规范化前做字符串映射，或改 **`_compound_covers` / `_compound_service_covers`** 里的比较逻辑。

## 7. Triple 索引键格式

文件：`src/fwintegrity/triple_index.py`

- 端点：`i:<cidr>`、`g:<object casefold>`
- 服务：`s:<proto>:<port>`、`sr:g:<name>`

与外部 CMDB/对象库对齐时，可约定 object 名预处理后再进 `parse_*`，或 fork 后改 **`endpoint_atom_keys` / `service_atom_keys`** 的前缀与拼接规则。

## 8. 已规范化数据直接接入

若你们已有自己的解析器，只要构造 **`NormalizedChange`**（`models.py`）即可复用 **`change_match`**、**`compare_changes`**、**`TicketTripleIndex`**，完全绕过 CSV 与 `parse_*`。

---

**发布 PyPI**：见仓库根目录 `README.md` 的 *Build and publish*；版本号需同时改 `pyproject.toml` 与 `src/fwintegrity/__init__.py` 中的 `__version__`。
