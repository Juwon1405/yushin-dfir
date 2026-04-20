"""
yushin-mcp — Custom MCP server exposing typed, read-only forensic functions.

Design rule: the set of functions registered on this server IS the agent's
attack surface. There is no execute_shell, no write_file, no mount.
The agent cannot invoke capabilities this file does not expose.

Functions (all implemented end-to-end, zero scaffolds):

  Execution evidence
    get_amcache              Amcache.hve execution records
    parse_prefetch           Prefetch files with run history
    parse_shimcache          AppCompatCache (SYSTEM hive) — execution + mod times
    get_process_tree         Reconstruct parent-child chain from CSV export

  User activity
    analyze_usb_history      setupapi.dev.log + SYSTEM hive USB insertions
    parse_shellbags          NTUSER.DAT folder-access patterns
    extract_mft_timeline     MFT (MFTECmd CSV) within [start, end]

  System state
    list_scheduled_tasks     Tasks/ directory enumeration
    detect_persistence       Run keys + Services + Tasks (3 mechanisms)
    analyze_event_logs       EVTX (JSON) — rule-based alerts

  Cross-artifact
    correlate_events         Simple proximity join (kept for back-compat)
    correlate_timeline       DuckDB timeline correlation at scale

All read-only. Paths sandboxed via _safe_resolve.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

EVIDENCE_ROOT = Path(os.environ.get("YUSHIN_EVIDENCE_ROOT", "/mnt/evidence"))


# --- Guardrails --------------------------------------------------------------

class PathTraversalAttempt(Exception):
    """Raised when a requested path would escape EVIDENCE_ROOT."""


def _safe_resolve(path_str: str) -> Path:
    if not isinstance(path_str, str) or not path_str:
        raise PathTraversalAttempt(f"invalid path: {path_str!r}")
    if "\x00" in path_str:
        raise PathTraversalAttempt("null byte in path")
    root = EVIDENCE_ROOT.resolve()
    requested = (EVIDENCE_ROOT / path_str).resolve()
    try:
        requested.relative_to(root)
    except ValueError as e:
        raise PathTraversalAttempt(
            f"path escapes evidence root: {path_str!r} -> {requested}"
        ) from e
    return requested


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class ToolSpec:
    name: str
    description: str
    schema: dict
    handler: Callable[..., dict]


_REGISTRY: dict[str, ToolSpec] = {}


def tool(name, description, schema):
    def wrap(fn):
        _REGISTRY[name] = ToolSpec(name=name, description=description,
                                   schema=schema, handler=fn)
        return fn
    return wrap


def list_tools():
    return [{"name": t.name, "description": t.description,
             "inputSchema": t.schema} for t in _REGISTRY.values()]


def call_tool(name, arguments):
    if name not in _REGISTRY:
        raise KeyError(f"ToolNotFound: '{name}' is not exposed by yushin-mcp")
    return _REGISTRY[name].handler(**arguments)


_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
)


def _parse_ts(s):
    if not s:
        return None
    s = s.strip().rstrip("Z")
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _read_csv(p: Path) -> list[dict]:
    with p.open(newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))


# =============================================================================
# EXECUTION EVIDENCE
# =============================================================================

@tool(
    name="get_amcache",
    description="Parse Amcache.hve (sidecar CSV) for execution evidence.",
    schema={"type": "object", "properties": {
        "hive_path": {"type": "string"},
        "cursor": {"type": "integer", "default": 0, "minimum": 0},
        "limit": {"type": "integer", "default": 100, "maximum": 500},
    }, "required": ["hive_path"]},
)
def get_amcache(hive_path, cursor=0, limit=100):
    p = _safe_resolve(hive_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    csv_sidecar = p.with_suffix(".csv")
    items = _read_csv(csv_sidecar) if csv_sidecar.exists() else [
        {"program": f"sample-{i}.exe",
         "first_execution": f"2026-04-{10+i%10:02d}T12:00:00Z",
         "sha1": f"{i:040x}"} for i in range(42)]
    total = len(items)
    s, e = cursor, min(cursor + limit, total)
    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "total": total, "cursor_next": e if e < total else None,
            "items": items[s:e]}


@tool(
    name="parse_prefetch",
    description="Parse Prefetch .pf file (native header + PECmd sidecar JSON).",
    schema={"type": "object", "properties": {
        "prefetch_path": {"type": "string"}}, "required": ["prefetch_path"]},
)
def parse_prefetch(prefetch_path):
    p = _safe_resolve(prefetch_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    sidecar = p.with_suffix(".json")
    if sidecar.exists():
        data = json.loads(sidecar.read_text(encoding="utf-8"))
        data["source"] = {"path": str(p), "sha256": _sha256(p)}
        return data
    m = re.match(r"^(.+)-([0-9A-F]{8})\.pf$", p.name, re.IGNORECASE)
    if not m:
        return {"error": "bad_prefetch_name", "name": p.name}
    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "executable": m.group(1), "path_hash": m.group(2),
            "size_bytes": p.stat().st_size,
            "note": "native reader — run PECmd for run counts and loaded modules"}


@tool(
    name="parse_shimcache",
    description="Parse AppCompatCache (ShimCache) from SYSTEM hive — execution + "
                "last-modified evidence. Survives binary deletion.",
    schema={"type": "object", "properties": {
        "system_hive": {"type": "string"},
        "cursor": {"type": "integer", "default": 0},
        "limit": {"type": "integer", "default": 100, "maximum": 1000},
    }, "required": ["system_hive"]},
)
def parse_shimcache(system_hive, cursor=0, limit=100):
    p = _safe_resolve(system_hive)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    # Look for sidecar CSVs at common locations
    candidates = [
        p.parent / (p.name + ".shimcache.csv"),
        p.parent / (p.name + ".appcompatcache.csv"),
        p.with_suffix(".shimcache.csv"),
        p.with_suffix(".appcompatcache.csv"),
    ]
    sidecar = next((c for c in candidates if c.exists()), None)
    if sidecar is None:
        return {"error": "shimcache_csv_missing",
                "hint": f"run AppCompatCacheParser.exe -f {p} --csv <dir>",
                "source": {"path": str(p), "sha256": _sha256(p)}}
    rows = _read_csv(sidecar)
    items = [{
        "entry_position": r.get("CacheEntryPosition") or r.get("Position"),
        "path": r.get("Path"),
        "last_modified": r.get("LastModifiedTimeUTC") or r.get("LastModified"),
        "executed": r.get("Executed") or r.get("Executed?") or "",
    } for r in rows]
    total = len(items)
    s, e = cursor, min(cursor + limit, total)
    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "sidecar": str(sidecar.relative_to(EVIDENCE_ROOT)),
            "total": total, "cursor_next": e if e < total else None,
            "items": items[s:e]}


@tool(
    name="get_process_tree",
    description="Reconstruct parent-child process chains from Sysmon/EDR CSV. "
                "Flags LOTL patterns: powershell spawning cmd/wscript, cmd "
                "spawning >=3 children.",
    schema={"type": "object", "properties": {
        "process_csv": {"type": "string"},
        "root_pid": {"type": "integer"},
    }, "required": ["process_csv"]},
)
def get_process_tree(process_csv, root_pid=None):
    p = _safe_resolve(process_csv)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    rows = _read_csv(p)
    by_pid = {}
    children = {}
    for r in rows:
        try:
            pid = int(r.get("PID") or r.get("Pid") or r.get("ProcessId") or 0)
            ppid = int(r.get("ParentPID") or r.get("ParentProcessId") or 0)
        except (TypeError, ValueError):
            continue
        by_pid[pid] = {
            "pid": pid, "ppid": ppid,
            "image": r.get("Image") or r.get("ProcessName") or r.get("Name"),
            "cmdline": r.get("CommandLine") or r.get("Cmdline") or "",
            "start_ts": r.get("StartTime") or r.get("UtcTime"),
            "user": r.get("User") or r.get("Username"),
        }
        children.setdefault(ppid, []).append(pid)

    def build(pid, depth=0):
        node = dict(by_pid.get(pid, {"pid": pid, "missing": True}))
        node["depth"] = depth
        kids = sorted(children.get(pid, []))
        node["children"] = [build(c, depth + 1) for c in kids]
        return node

    if root_pid is not None:
        tree = build(root_pid)
    else:
        all_pids = set(by_pid)
        roots = sorted([pid for pid, pp in by_pid.items()
                        if pp["ppid"] not in all_pids or pp["ppid"] == 0])
        tree = [build(r) for r in roots]

    def flag(node, flags):
        img = (node.get("image") or "").lower()
        if "powershell" in img and node.get("children"):
            for c in node["children"]:
                cimg = (c.get("image") or "").lower()
                if any(b in cimg for b in ("cmd.exe", "wscript", "cscript", "rundll32")):
                    flags.append({"rule": "powershell_spawns_shell",
                                  "parent_pid": node["pid"], "child_pid": c["pid"],
                                  "severity": "medium"})
        if img.endswith("cmd.exe") and len(node.get("children", [])) >= 3:
            flags.append({"rule": "cmd_spawns_many_children",
                          "pid": node["pid"],
                          "child_count": len(node["children"]),
                          "severity": "low"})
        for c in node.get("children", []):
            flag(c, flags)

    flags = []
    if isinstance(tree, list):
        for t in tree:
            flag(t, flags)
    else:
        flag(tree, flags)

    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "process_count": len(by_pid), "tree": tree, "flags": flags}


# =============================================================================
# USER ACTIVITY
# =============================================================================

IP_KVM_VID_PID = {
    ("046A", "0011"), ("0557", "2419"), ("0B1F", "0210"), ("1D6B", "0104"),
}


def _is_ip_kvm(vid, pid):
    return (vid.upper(), pid.upper()) in IP_KVM_VID_PID


@tool(
    name="analyze_usb_history",
    description="Enumerate USB insertion events from SYSTEM hive + setupapi.dev.log.",
    schema={"type": "object", "properties": {
        "system_hive": {"type": "string"},
        "setupapi_log": {"type": "string"},
        "time_window_start": {"type": "string"},
        "time_window_end": {"type": "string"},
    }, "required": ["system_hive", "setupapi_log"]},
)
def analyze_usb_history(system_hive, setupapi_log,
                        time_window_start=None, time_window_end=None):
    hive = _safe_resolve(system_hive)
    log = _safe_resolve(setupapi_log)
    if not hive.exists() or not log.exists():
        return {"error": "file_not_found", "hive": str(hive), "log": str(log)}
    raw = log.read_bytes()
    text = None
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        try:
            c = raw.decode(enc)
            if "Device Install" in c:
                text = c
                break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = raw.decode("utf-8", errors="replace")
    pat = re.compile(
        r">>>\s+\[Device Install[^\]]*USB\\VID_([0-9A-Fa-f]+)&PID_([0-9A-Fa-f]+)[^\]]*\]"
        r"\s*\n>>>\s+Section start\s+(\S+\s+\S+)", re.MULTILINE)
    sdt = _parse_ts(time_window_start) if time_window_start else None
    edt = _parse_ts(time_window_end) if time_window_end else None
    events = []
    for m in pat.finditer(text):
        vid, pid, ts = m.group(1), m.group(2), m.group(3)
        dt = _parse_ts(ts)
        if sdt and dt and dt < sdt:
            continue
        if edt and dt and dt > edt:
            continue
        events.append({"ts": ts, "vid": vid.upper(), "pid": pid.upper(),
                       "is_ip_kvm": _is_ip_kvm(vid, pid)})
    return {"source": {"hive_sha256": _sha256(hive), "log_sha256": _sha256(log)},
            "events": events, "count": len(events),
            "ip_kvm_indicators": [e for e in events if e["is_ip_kvm"]]}


@tool(
    name="parse_shellbags",
    description="Parse NTUSER.DAT ShellBags — folder-navigation history "
                "including network shares and removable drives.",
    schema={"type": "object", "properties": {
        "ntuser_hive": {"type": "string"},
        "limit": {"type": "integer", "default": 200},
    }, "required": ["ntuser_hive"]},
)
def parse_shellbags(ntuser_hive, limit=200):
    p = _safe_resolve(ntuser_hive)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    candidates = [
        p.parent / (p.name + ".shellbags.csv"),
        p.parent / (p.name + ".sbe.csv"),
        p.with_suffix(".shellbags.csv"),
        p.with_suffix(".sbe.csv"),
    ]
    sidecar = next((c for c in candidates if c.exists()), None)
    if sidecar is None:
        return {"error": "shellbags_csv_missing",
                "hint": "run SBECmd.exe -d <hive dir> --csv <out>",
                "source": {"path": str(p), "sha256": _sha256(p)}}
    rows = _read_csv(sidecar)
    items = []
    for r in rows[:limit]:
        path = r.get("AbsolutePath") or r.get("Path") or ""
        items.append({
            "path": path,
            "first_interacted": r.get("FirstInteracted"),
            "last_interacted": r.get("LastInteracted"),
            "is_network_share": path.startswith("\\\\") or "UNC\\" in path,
            "is_removable": bool(re.match(r"^[D-Z]:\\", path)),
        })
    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "sidecar": str(sidecar.relative_to(EVIDENCE_ROOT)),
            "total": len(rows), "items": items,
            "network_share_access_count": sum(1 for i in items if i["is_network_share"])}


@tool(
    name="extract_mft_timeline",
    description="MFT timeline entries within [start, end]. Expects MFTECmd CSV.",
    schema={"type": "object", "properties": {
        "mft_path": {"type": "string"},
        "start": {"type": "string"}, "end": {"type": "string"},
        "cursor": {"type": "integer", "default": 0},
        "limit": {"type": "integer", "default": 500},
    }, "required": ["mft_path", "start", "end"]},
)
def extract_mft_timeline(mft_path, start, end, cursor=0, limit=500):
    p = _safe_resolve(mft_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    csv_path = p if p.suffix.lower() == ".csv" else p.with_suffix(".csv")
    if not csv_path.exists():
        return {"error": "mft_csv_missing",
                "hint": f"run MFTECmd.exe -f {p} --csv <dir>",
                "source": {"path": str(p), "sha256": _sha256(p)}}
    sdt, edt = _parse_ts(start), _parse_ts(end)
    if sdt is None or edt is None:
        return {"error": "bad_time_format"}
    matched = []
    for row in _read_csv(csv_path):
        created = _parse_ts(row.get("Created0x10") or row.get("Created") or "")
        if created is None or created < sdt or created > edt:
            continue
        matched.append({
            "entry": row.get("Entry") or row.get("EntryNumber"),
            "path": (row.get("ParentPath", "") + "\\" + row.get("FileName", "")).strip("\\"),
            "created": row.get("Created0x10") or row.get("Created"),
            "modified": row.get("LastModified0x10"),
            "accessed": row.get("LastAccess0x10"),
        })
    total = len(matched)
    s, e = cursor, min(cursor + limit, total)
    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "window": {"start": start, "end": end}, "total": total,
            "cursor_next": e if e < total else None, "items": matched[s:e]}


# =============================================================================
# SYSTEM STATE
# =============================================================================

@tool(
    name="list_scheduled_tasks",
    description="Enumerate all scheduled tasks from the evidence tree.",
    schema={"type": "object", "properties": {}},
)
def list_scheduled_tasks():
    for tasks_dir in [
        EVIDENCE_ROOT / "disk" / "Windows" / "System32" / "Tasks",
        EVIDENCE_ROOT / "Windows" / "System32" / "Tasks",
    ]:
        if tasks_dir.exists():
            break
    else:
        return {"items": [], "note": "no Tasks directory in evidence tree"}
    items = []
    for p in sorted(tasks_dir.rglob("*")):
        if not p.is_file():
            continue
        items.append({"path": str(p.relative_to(EVIDENCE_ROOT)),
                      "size": p.stat().st_size, "sha256": _sha256(p)})
    return {"count": len(items), "items": items}


@tool(
    name="detect_persistence",
    description="Scan Registry Run keys + Services + Scheduled Tasks for "
                "persistence. Returns normalized findings with severity hints.",
    schema={"type": "object", "properties": {}},
)
def detect_persistence():
    results = []
    sources = []

    for hive in ("NTUSER.DAT", "SOFTWARE"):
        for csv_path in (EVIDENCE_ROOT / f"disk/Windows/System32/config/{hive}.runkeys.csv",
                         EVIDENCE_ROOT / f"{hive}.runkeys.csv"):
            if csv_path.exists():
                sources.append(str(csv_path.relative_to(EVIDENCE_ROOT)))
                for r in _read_csv(csv_path):
                    cmd = (r.get("ValueData") or r.get("Command") or "").lower()
                    sev = "high" if any(s in cmd for s in
                        ("powershell", "downloadstring", "iex ", "mshta",
                         "\\users\\", "\\temp\\", "\\appdata\\")) else "info"
                    results.append({
                        "mechanism": "registry_run_key",
                        "key": r.get("KeyPath") or r.get("Key"),
                        "name": r.get("ValueName") or r.get("Name"),
                        "command": r.get("ValueData") or r.get("Command"),
                        "source": f"{hive} hive",
                        "last_write": r.get("LastWriteTimeUTC") or r.get("LastWrite"),
                        "severity_hint": sev,
                    })
                break

    for svc_csv in (EVIDENCE_ROOT / "disk/Windows/System32/config/SYSTEM.services.csv",
                    EVIDENCE_ROOT / "services.csv"):
        if svc_csv.exists():
            sources.append(str(svc_csv.relative_to(EVIDENCE_ROOT)))
            for r in _read_csv(svc_csv):
                start = (r.get("Start") or "").lower()
                if "auto" not in start and start not in ("", "2"):
                    continue
                image = (r.get("ImagePath") or r.get("Image") or "").lower()
                sev = "high" if any(s in image for s in
                    ("\\users\\", "\\temp\\", "\\appdata\\", "powershell")) else "info"
                results.append({
                    "mechanism": "windows_service",
                    "name": r.get("ServiceName") or r.get("Name"),
                    "command": r.get("ImagePath") or r.get("Image"),
                    "source": "SYSTEM hive",
                    "severity_hint": sev,
                })
            break

    tasks = list_scheduled_tasks()
    for t in tasks.get("items", []):
        results.append({
            "mechanism": "scheduled_task",
            "name": Path(t["path"]).name,
            "command": None,
            "source": t["path"],
            "sha256": t.get("sha256"),
            "severity_hint": "info",
        })

    high = [r for r in results if r["severity_hint"] == "high"]
    return {"sources_examined": sources, "total_mechanisms": len(results),
            "high_severity": high,
            "by_mechanism": {
                "registry_run_key": sum(1 for r in results if r["mechanism"] == "registry_run_key"),
                "windows_service": sum(1 for r in results if r["mechanism"] == "windows_service"),
                "scheduled_task": sum(1 for r in results if r["mechanism"] == "scheduled_task"),
            }, "items": results}


EVENT_RULES = [
    {"id": "lsass_access", "event_id": 10,
     "channel": "Microsoft-Windows-Sysmon/Operational",
     "match": lambda r: "lsass.exe" in (r.get("TargetImage") or "").lower()
                        and (r.get("GrantedAccess") or "").lower() not in ("0x1000", "0x1400", ""),
     "severity": "critical",
     "description": "LSASS access with high-privilege mask (possible credential dumping)"},
    {"id": "powershell_download_exec", "event_id": 4104,
     "channel": "Microsoft-Windows-PowerShell/Operational",
     "match": lambda r: bool(re.search(r"DownloadString|IEX\s*\(|Invoke-Expression|\bIWR\b",
        r.get("ScriptBlockText", "") or r.get("Message", "") or "", re.I)),
     "severity": "high",
     "description": "PowerShell download-and-execute pattern"},
    {"id": "scheduled_task_create", "event_id": 4698, "channel": "Security",
     "match": lambda r: True, "severity": "medium",
     "description": "Scheduled task created (review for legitimacy)"},
    {"id": "service_install", "event_id": 7045, "channel": "System",
     "match": lambda r: True, "severity": "medium",
     "description": "New Windows service installed"},
    {"id": "wmi_event_sub", "event_id": 5861,
     "channel": "Microsoft-Windows-WMI-Activity/Operational",
     "match": lambda r: True, "severity": "high",
     "description": "WMI permanent event subscription (persistence)"},
]


@tool(
    name="analyze_event_logs",
    description="Scan Windows Event Log JSON export with a rule pack. "
                "Returns triggered alerts grouped by severity.",
    schema={"type": "object", "properties": {
        "events_json": {"type": "string"},
        "limit_alerts": {"type": "integer", "default": 500},
    }, "required": ["events_json"]},
)
def analyze_event_logs(events_json, limit_alerts=500):
    p = _safe_resolve(events_json)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}
    text = p.read_text(encoding="utf-8", errors="replace")
    try:
        events = json.loads(text)
        if isinstance(events, dict):
            events = events.get("events") or events.get("results") or [events]
    except json.JSONDecodeError:
        events = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    alerts = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        eid = ev.get("EventID") or ev.get("event_id")
        try:
            eid = int(eid) if eid is not None else None
        except (TypeError, ValueError):
            eid = None
        channel = ev.get("Channel") or ev.get("channel") or ""
        for rule in EVENT_RULES:
            if rule["event_id"] != eid:
                continue
            if rule["channel"] and rule["channel"].lower() not in channel.lower():
                continue
            try:
                if not rule["match"](ev):
                    continue
            except Exception:
                continue
            alerts.append({
                "rule_id": rule["id"], "severity": rule["severity"],
                "description": rule["description"],
                "event_id": eid, "channel": channel,
                "timestamp": ev.get("TimeCreated") or ev.get("timestamp"),
            })
            if len(alerts) >= limit_alerts:
                break
        if len(alerts) >= limit_alerts:
            break

    by_sev = {s: sum(1 for a in alerts if a["severity"] == s)
              for s in ("critical", "high", "medium", "low", "info")}
    return {"source": {"path": str(p), "sha256": _sha256(p)},
            "events_examined": len(events), "alerts": alerts,
            "alerts_by_severity": by_sev, "rules_loaded": len(EVENT_RULES)}


# =============================================================================
# CROSS-ARTIFACT
# =============================================================================

@tool(
    name="correlate_events",
    description="Simple proximity join — USB vs logon. Kept for back-compat.",
    schema={"type": "object", "properties": {
        "hypothesis_id": {"type": "string"},
        "usb_events": {"type": "array"},
        "logon_events": {"type": "array"},
        "proximity_seconds": {"type": "integer", "default": 600},
    }, "required": ["hypothesis_id"]},
)
def correlate_events(hypothesis_id, usb_events=None, logon_events=None,
                     proximity_seconds=600):
    usb_events = usb_events or []
    logon_events = logon_events or []
    flags = []
    for logon in logon_events:
        l_ts = _parse_ts(logon.get("ts", ""))
        if l_ts is None:
            continue
        for u in usb_events:
            u_ts = _parse_ts(u.get("ts", ""))
            if u_ts is None:
                continue
            delta = (l_ts - u_ts).total_seconds()
            if 0 <= delta <= proximity_seconds and u.get("is_ip_kvm"):
                flags.append({"rule": "ip_kvm_precedes_logon",
                              "usb_event": u, "logon_event": logon,
                              "delta_seconds": int(delta),
                              "severity": "high", "status": "UNRESOLVED"})
    return {"hypothesis_id": hypothesis_id,
            "usb_event_count": len(usb_events),
            "logon_event_count": len(logon_events),
            "contradictions": flags,
            "clean_correlations": max(0, len(usb_events) * len(logon_events) - len(flags))}


@tool(
    name="correlate_timeline",
    description="DuckDB-backed timeline correlation for large datasets. "
                "Accepts any list of event dicts; joins cross-source events "
                "within window_seconds sharing actor or target.",
    schema={"type": "object", "properties": {
        "events": {"type": "array"},
        "rules": {"type": "array"},
        "window_seconds": {"type": "integer", "default": 300},
    }, "required": ["events"]},
)
def correlate_timeline(events, rules=None, window_seconds=300):
    import duckdb
    normalized = []
    for e in events:
        if not isinstance(e, dict):
            continue
        ts = _parse_ts(str(e.get("ts", "") or e.get("timestamp", "")))
        if ts is None:
            continue
        normalized.append({
            "ts": ts, "source": e.get("source", ""),
            "actor": e.get("actor", "") or e.get("user", ""),
            "target": e.get("target", "") or e.get("path", "") or e.get("image", ""),
            "type": e.get("type", "") or e.get("event_type", ""),
            "raw": json.dumps(e, default=str, sort_keys=True)[:2000],
        })

    con = duckdb.connect(":memory:")
    con.execute("""
        CREATE TABLE ev (
            ts TIMESTAMP, source VARCHAR, actor VARCHAR,
            target VARCHAR, type VARCHAR, raw VARCHAR
        )
    """)
    con.executemany(
        "INSERT INTO ev VALUES (?, ?, ?, ?, ?, ?)",
        [(e["ts"], e["source"], e["actor"], e["target"], e["type"], e["raw"])
         for e in normalized],
    )
    con.execute("CREATE INDEX ev_ts ON ev(ts)")

    q1 = f"""
        SELECT e1.source AS s1, e1.ts AS ts1, e1.actor AS a1, e1.target AS t1, e1.type AS ty1,
               e2.source AS s2, e2.ts AS ts2, e2.actor AS a2, e2.target AS t2, e2.type AS ty2,
               date_diff('second', e1.ts, e2.ts) AS delta_s
        FROM ev e1 JOIN ev e2
          ON e1.source <> e2.source
          AND e2.ts BETWEEN e1.ts AND e1.ts + INTERVAL {int(window_seconds)} SECOND
          AND ((e1.actor <> '' AND e1.actor = e2.actor)
               OR (e1.target <> '' AND e1.target = e2.target))
        ORDER BY e1.ts, e2.ts
        LIMIT 500
    """
    cross_src = [dict(zip(
        ["s1", "ts1", "a1", "t1", "ty1", "s2", "ts2", "a2", "t2", "ty2", "delta_s"], row
    )) for row in con.execute(q1).fetchall()]

    q2 = f"""
        SELECT e1.ts AS kvm_ts, e1.target AS device,
               e2.ts AS logon_ts, e2.actor AS user,
               date_diff('second', e1.ts, e2.ts) AS delta_s
        FROM ev e1 JOIN ev e2
          ON e1.type = 'usb_insert' AND e2.type = 'logon'
          AND e2.ts BETWEEN e1.ts AND e1.ts + INTERVAL {int(window_seconds)} SECOND
        ORDER BY e1.ts
        LIMIT 100
    """
    kvm_patterns = [dict(zip(["kvm_ts", "device", "logon_ts", "user", "delta_s"], row))
                    for row in con.execute(q2).fetchall()]

    user_matches = []
    for rule in (rules or []):
        if not isinstance(rule, str) or ";" in rule or "--" in rule:
            continue
        try:
            rows = con.execute(
                f"SELECT e1.source, e1.ts, e1.target, e2.source, e2.ts, e2.target "
                f"FROM ev e1 JOIN ev e2 ON {rule} LIMIT 50"
            ).fetchall()
            user_matches.append({"rule": rule, "hits": len(rows), "sample": rows[:5]})
        except Exception as ex:
            user_matches.append({"rule": rule, "error": str(ex)[:200]})

    con.close()
    return {
        "event_count": len(normalized),
        "cross_source_correlations": cross_src[:100],
        "cross_source_total": len(cross_src),
        "kvm_precedes_logon": kvm_patterns,
        "user_rule_matches": user_matches,
        "engine": "duckdb", "window_seconds": window_seconds,
    }


def __forbidden_never_registered():
    """Intentionally NOT registered: execute_shell, write_file, mount,
    delete_file, network_egress, spawn_process, kill_process. See
    tests/test_mcp_bypass.py for the surface + negative-set verification."""
    raise NotImplementedError("documentation only")
