const SAMPLE_AUDIT = `Hostname,Change Type,Policy,Number,Name,Scope,Status,Source Zone,Source,User,Destination Zone,Destination,Application,Service,URL Category,Action,Security Profile,TCP Falgs,Schedule Object,Logging,Vendor Tag
fw-core,Add,POL-EDGE,10,r1,,ok,,IP_10.10.10.10 IP_10.10.10.11,,,Host_10.20.20.20,,TCP_443 TCP_80,,allow,,,,,
fw-core,Add,POL-ICMP,11,r2,,ok,,192.168.0.1,,,192.168.0.2,,ICMP/8,,allow,,,,,
fw-dmz,Add,POL-DMZ,20,r3,,ok,,172.16.5.1,,,172.16.6.10,,UDP_53,,allow,,,,,
fw-core,Add,POL-ORPH,99,rx,,ok,,10.255.1.1,,,10.255.2.2,,tcp/9999,,allow,,,,,
`;

const SAMPLE_TICKET = `Ticket Number,INF Number,Action,Source IP Address,Destination IP Address,Service Port
CHG-100,INF-A001,Add,"10.10.10.10, 10.10.10.11",10.20.20.20,TCP 443 TCP 80
CHG-100,INF-A002,Add,192.168.0.1,192.168.0.2,ICMP/8
CHG-200,INF-B001,Add,172.16.5.1,172.16.6.10,UDP 53
CHG-200,INF-B001,Add,172.16.5.2,172.16.6.11,udp/53
`;

const RUN_PY = `
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

def run_compare(audit_csv, ticket_csv):
    ign = merged_ignored_service_names(None)
    ticket_rows = load_change_rows(from_csv_text(ticket_csv), TICKET_CSV_DEFAULT_MAPPING)
    audit_rows = load_change_rows(from_csv_text(audit_csv), AUDIT_EXPORT_DEFAULT_MAPPING)
    idx = build_ticket_triple_index(ticket_rows, ignored_services=ign)
    out = {"link": [], "triple_check": [], "meta": {"ticket_rows": len(ticket_rows), "audit_rows": len(audit_rows)}}
    links = link_audit_to_ticket_requests(audit_rows, ticket_rows, ignored_services=ign)
    for L in links:
        out["link"].append({
            "audit_row": L.audit_row_index,
            "change": L.audit.change.value if L.audit else None,
            "ticket_numbers": list(L.ticket_numbers),
            "inf_numbers": list(L.inf_numbers),
            "parse_msgs": list(L.audit_parse_messages),
        })
    audits = audit_rows_to_changes(audit_rows)
    for i, ach in enumerate(audits):
        ok, miss = audit_triples_all_in_index(ach, idx, ignored_services=ign)
        out["triple_check"].append({
            "audit_row_norm_index": i,
            "all_triples_in_index": ok,
            "missing_count": len(miss),
            "missing_sample": miss[:5],
        })
    return json.dumps(out, ensure_ascii=False, indent=2)

run_compare(AUDIT_CSV, TICKET_CSV)
`;

let pyodide = null;
let lastResult = null;
let activeTab = "link";

async function fetchVersionConfig() {
  const res = await fetch("version.json", { cache: "no-store" });
  if (!res.ok) return { version: "0.4.0", package: "fwintegrity" };
  return res.json();
}

function setStatus(text, kind) {
  const el = document.getElementById("status");
  el.textContent = text;
  el.className = kind || "";
}

function renderOutput() {
  const out = document.getElementById("output");
  if (!lastResult) {
    out.textContent = "等待运行…";
    return;
  }
  if (activeTab === "raw") {
    out.textContent = lastResult;
    return;
  }
  try {
    const data = JSON.parse(lastResult);
    if (activeTab === "link") {
      out.textContent = JSON.stringify(data.link, null, 2);
    } else {
      out.textContent = JSON.stringify(data.triple_check, null, 2);
    }
  } catch {
    out.textContent = lastResult;
  }
}

async function initPyodide() {
  const cfg = await fetchVersionConfig();
  const pkg = cfg.package || "fwintegrity";
  const ver = cfg.version || "0.4.0";
  setStatus("加载 Pyodide…");
  try {
    pyodide = await loadPyodide();
    setStatus(`安装 ${pkg}==${ver}…`);
    await pyodide.loadPackage("micropip");
    const micropip = pyodide.pyimport("micropip");
    await micropip.install(`${pkg}==${ver}`);
    const installed = pyodide.runPython("import fwintegrity; fwintegrity.__version__");
    document.getElementById("pkg-version").textContent = `v${installed}`;
    setStatus("就绪", "ready");
    document.getElementById("run").disabled = false;
  } catch (e) {
    console.error(e);
    setStatus(`初始化失败: ${e.message || e}`, "error");
  }
}

async function runCompare() {
  if (!pyodide) return;
  const runBtn = document.getElementById("run");
  runBtn.disabled = true;
  setStatus("运行中…");
  try {
    pyodide.globals.set("AUDIT_CSV", document.getElementById("audit").value);
    pyodide.globals.set("TICKET_CSV", document.getElementById("ticket").value);
    lastResult = pyodide.runPython(RUN_PY);
    renderOutput();
    setStatus("完成", "ready");
  } catch (e) {
    console.error(e);
    document.getElementById("output").textContent = String(e.message || e);
    setStatus("运行出错", "error");
  } finally {
    runBtn.disabled = false;
  }
}

function loadSample() {
  document.getElementById("audit").value = SAMPLE_AUDIT;
  document.getElementById("ticket").value = SAMPLE_TICKET;
}

document.getElementById("run").addEventListener("click", runCompare);
document.getElementById("sample").addEventListener("click", loadSample);
document.querySelectorAll(".tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    activeTab = btn.dataset.tab;
    renderOutput();
  });
});

loadSample();
initPyodide();
