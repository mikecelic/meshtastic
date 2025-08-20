#!/usr/bin/env python3
# meshtastic_webui_standalone_v1_2.py
#
# Single-file Meshtastic Web UI with zero external Python deps.
# v1.2 adds:
#   - Default HOST=0.0.0.0 (LAN accessible)
#   - Messages tab: sortable headers for all columns
#   - Local timezone rendering in the browser (Overview, Node Detail, Messages, charts)
#   - Node Detail: Radio Quality first, then Telemetry
#   - Node Detail: Leaflet map under Telemetry if GPS positions exist
#
# Run:
#   python3 meshtastic_webui_standalone_v1_2.py
#   open http://<your-ip>:8080
#
# Expected logs:
#   ./meshtastic_logs/<LABEL>/<LABEL>_YYYY-MM-DD_HH.ndjson

from __future__ import annotations
import json, os, re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any, Dict, List, Optional, Tuple

# -------------------------
# Config
# -------------------------
HOST = "0.0.0.0"   # default bind to all interfaces
PORT = 8080
DEFAULT_LOG_ROOT = "./meshtastic_logs"
DEFAULT_LABEL: Optional[str] = None
MAX_LOOKBACK_HOURS = 168
MAX_MESSAGES_RETURN = 5000

# -------------------------
# Helpers
# -------------------------
HOUR_RE = re.compile(r".*_(\d{4}-\d{2}-\d{2})_(\d{2})\.ndjson$")

def parse_hour_from_filename(p: Path) -> Optional[datetime]:
    m = HOUR_RE.match(p.name)
    if not m: return None
    day, hour = m.groups()
    try:
        return datetime.fromisoformat(f"{day}T{hour}:00:00+00:00")
    except Exception:
        return None

def to_utc(dt_str: Optional[str]) -> Optional[datetime]:
    if not dt_str: return None
    try:
        return datetime.fromisoformat(dt_str).astimezone(timezone.utc)
    except Exception:
        return None

def iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None

def app_name_from_portnum(portnum: Any) -> str:
    if isinstance(portnum, str) and portnum:
        return portnum
    if isinstance(portnum, int):
        return {1:"TEXT_MESSAGE_APP",3:"POSITION_APP",67:"TELEMETRY_APP"}.get(portnum, f"PORT_{portnum}")
    return "UNKNOWN"

def safe_float(x: Any) -> Optional[float]:
    try:
        if x is None: return None
        return float(x)
    except Exception:
        return None

def safe_int(x: Any) -> Optional[int]:
    try:
        if x is None: return None
        return int(x)
    except Exception:
        return None

def norm_node_ids(pkt: dict) -> Tuple[Optional[str], Optional[str]]:
    fid = pkt.get("fromId")
    tid = pkt.get("toId")
    if fid is None and "from" in pkt: fid = str(pkt.get("from"))
    if tid is None and "to" in pkt:   tid = str(pkt.get("to"))
    return (str(fid) if fid is not None else None,
            str(tid) if tid is not None else None)

def detect_my_node_from_snapshots(snapshots: List[dict]) -> Optional[str]:
    for s in snapshots:
        mi = s.get("myInfo") or {}
        user = mi.get("user") or {}
        uid = user.get("id")
        if uid: return str(uid)
    return None

def harvest_name_map_from_snapshots(snapshots: List[dict]) -> Dict[str, Dict[str,str]]:
    name_map: Dict[str, Dict[str,str]] = {}
    for s in snapshots:
        mi = s.get("myInfo") or {}
        u = mi.get("user") or {}
        uid = u.get("id")
        if uid:
            d = name_map.setdefault(str(uid), {})
            if u.get("shortName"): d["short"] = str(u.get("shortName"))
            if u.get("longName"):  d["long"]  = str(u.get("longName"))
        nodes = s.get("nodes")
        if isinstance(nodes, dict):
            for nd in nodes.values():
                u2 = (nd or {}).get("user") or {}
                nid = u2.get("id")
                if not nid: continue
                d2 = name_map.setdefault(str(nid), {})
                if u2.get("shortName"): d2["short"] = str(u2.get("shortName"))
                if u2.get("longName"):  d2["long"]  = str(u2.get("longName"))
    return name_map

def list_labels(log_root: Path) -> List[str]:
    if not log_root.exists(): return []
    labs = [p.name for p in log_root.iterdir() if p.is_dir()]
    labs.sort()
    return labs

# -------------------------
# Core loading & shaping
# -------------------------
class DataBundle:
    def __init__(self):
        self.messages: List[dict] = []
        self.snapshots: List[dict] = []
        self.name_map: Dict[str, Dict[str,str]] = {}
        self.my_node_id: Optional[str] = None
        self.files_loaded: List[str] = []
        self.app_set: set = set()

def _extract_position(decoded: dict) -> Optional[dict]:
    pos = decoded.get("position") or {}
    if not isinstance(pos, dict): return None
    lat = pos.get("latitude")
    lon = pos.get("longitude")
    if lat is None or lon is None:
        # try integer microdegrees if present
        latI = pos.get("latitudeI")
        lonI = pos.get("longitudeI")
        try:
            if latI is not None and lonI is not None:
                lat = float(latI) / 1e7
                lon = float(lonI) / 1e7
        except Exception:
            pass
    if lat is None or lon is None:
        return None
    out = {
        "lat": float(lat),
        "lon": float(lon),
    }
    if "altitude" in pos: out["altitude"] = safe_float(pos.get("altitude"))
    if "satsInView" in pos: out["satsInView"] = safe_int(pos.get("satsInView"))
    return out

def load_bundle(log_root: str, label: str, mode: str, hours: int) -> DataBundle:
    root = Path(log_root).expanduser().resolve()
    label_dir = root / label
    out = DataBundle()
    if not label_dir.exists():
        return out

    files = sorted([str(p) for p in label_dir.glob(f"{label}_*.ndjson")])
    if not files:
        return out

    if mode == "lastfile":
        chosen = [max(files, key=lambda f: os.path.getmtime(f))]
    else:
        hours = max(1, min(hours, MAX_LOOKBACK_HOURS))
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=hours)
        chosen = []
        for f in files:
            dt = parse_hour_from_filename(Path(f))
            if dt and dt >= cutoff.replace(minute=0, second=0, microsecond=0):
                chosen.append(f)
        if not chosen:
            chosen = [files[-1]]

    out.files_loaded = [Path(f).name for f in chosen]

    for f in chosen:
        try:
            with open(f, "r", encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if not line: continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        continue
                    et = ev.get("type")
                    if et and et.startswith("snapshot"):
                        out.snapshots.append({
                            "ts": ev.get("ts"),
                            "myInfo": ev.get("myInfo"),
                            "nodes": ev.get("nodes"),
                            "radioConfig": ev.get("radioConfig"),
                        })
                        continue
                    if et in ("rx","tx_echo"):
                        pkt = ev.get("packet") or {}
                        decoded = pkt.get("decoded") or {}
                        app = app_name_from_portnum(decoded.get("portnum", decoded.get("payloadVariant")))
                        from_id, to_id = norm_node_ids(pkt)
                        pos = _extract_position(decoded)
                        msg = {
                            "ts": ev.get("ts"),
                            "etype": et,
                            "from_id": from_id,
                            "to_id": to_id,
                            "app": app,
                            "text": decoded.get("text"),
                            "channel": pkt.get("channel"),
                            "rxRssi": safe_float(pkt.get("rxRssi")),
                            "rxSnr": safe_float(pkt.get("rxSnr")),
                            "hopLimit": safe_int(pkt.get("hopLimit")),
                            "hopStart": safe_int(pkt.get("hopStart")),
                            "relayNode": pkt.get("relayNode"),
                            "priority": pkt.get("priority"),
                            "id": pkt.get("id"),
                            "is_encrypted": bool(pkt.get("encrypted") or pkt.get("pkiEncrypted")),
                            "decoded_isPrivate": bool(decoded.get("isPrivate")) if decoded.get("isPrivate") is not None else None,
                            "decoded_dm": bool(decoded.get("dm")) if decoded.get("dm") is not None else None,
                            "telemetry": decoded.get("telemetry") or {},
                            "position": pos,
                        }
                        out.messages.append(msg)
                        out.app_set.add(app)
        except Exception:
            continue

    out.name_map = harvest_name_map_from_snapshots(out.snapshots)
    out.my_node_id = detect_my_node_from_snapshots(out.snapshots)
    return out

def latest_by_node_telemetry(messages: List[dict]) -> Tuple[Dict[str,dict], Dict[str,dict], Dict[str,dict]]:
    dev_last: Dict[str, dict] = {}
    env_last: Dict[str, dict] = {}
    loc_last: Dict[str, dict] = {}
    for m in messages:
        nid = m.get("from_id")
        tel = m.get("telemetry") or {}
        if not nid or not tel: continue
        ts = to_utc(m.get("ts"))
        if "deviceMetrics" in tel and isinstance(tel["deviceMetrics"], dict):
            dev_last[nid] = {"ts": iso(ts), **tel["deviceMetrics"]}
        if "environmentMetrics" in tel and isinstance(tel["environmentMetrics"], dict):
            env_last[nid] = {"ts": iso(ts), **tel["environmentMetrics"]}
        if "localStats" in tel and isinstance(tel["localStats"], dict):
            loc_last[nid] = {"ts": iso(ts), **tel["localStats"]}
    return dev_last, env_last, loc_last

def build_overview(bundle: DataBundle, include_encrypted: bool, apps_filter: Optional[List[str]]) -> dict:
    msgs = bundle.messages
    if not include_encrypted:
        msgs = [m for m in msgs if not m.get("is_encrypted")]
    if apps_filter:
        apps_set = set(apps_filter)
        msgs = [m for m in msgs if m.get("app") in apps_set]

    by_node: Dict[str, dict] = {}
    for m in msgs:
        nid = m.get("from_id")
        if not nid: continue
        ts = to_utc(m.get("ts"))
        rec = by_node.setdefault(nid, {
            "first_heard": None, "last_heard": None,
            "total_msgs": 0,
            "rssi_vals": [], "snr_vals": [],
            "app_counts": {}
        })
        rec["total_msgs"] += 1
        if ts:
            if rec["first_heard"] is None or ts < rec["first_heard"]: rec["first_heard"] = ts
            if rec["last_heard"] is None or ts > rec["last_heard"]:   rec["last_heard"] = ts
        rssi = m.get("rxRssi"); snr = m.get("rxSnr")
        if rssi is not None: rec["rssi_vals"].append(rssi)
        if snr  is not None: rec["snr_vals"].append(snr)
        app = m.get("app") or "UNKNOWN"
        rec["app_counts"][app] = rec["app_counts"].get(app, 0) + 1

    dev_last, env_last, _ = latest_by_node_telemetry(bundle.messages)

    rows: List[dict] = []
    for nid, rec in by_node.items():
        nameinfo = bundle.name_map.get(nid, {})
        row = {
            "node_id": nid,
            "name": nameinfo.get("short") or nameinfo.get("long") or nid,
            "first_heard": iso(rec["first_heard"]),
            "last_heard": iso(rec["last_heard"]),
            "total_msgs": rec["total_msgs"],
            "median_rssi": (median(rec["rssi_vals"]) if rec["rssi_vals"] else None),
            "median_snr":  (median(rec["snr_vals"])  if rec["snr_vals"]  else None),
            "app_counts": rec["app_counts"],
            "device": dev_last.get(nid),
            "environment": env_last.get(nid),
        }
        rows.append(row)

    rows.sort(key=lambda r: r["last_heard"] or "", reverse=True)

    return {
        "files_loaded": bundle.files_loaded,
        "my_node_id": bundle.my_node_id,
        "apps_available": sorted(list(bundle.app_set)),
        "nodes": rows
    }

def build_node_detail(bundle: DataBundle, node_id: str, include_encrypted: bool, apps_filter: Optional[List[str]]) -> dict:
    msgs = bundle.messages
    if not include_encrypted:
        msgs = [m for m in msgs if not m.get("is_encrypted")]
    if apps_filter:
        apps_set = set(apps_filter)
        msgs = [m for m in msgs if m.get("app") in apps_set]
    msgs = [m for m in msgs if m.get("from_id") == node_id]

    ts_list = [to_utc(m.get("ts")) for m in msgs if to_utc(m.get("ts"))]
    rssi_vals = [m.get("rxRssi") for m in msgs if m.get("rxRssi") is not None]
    snr_vals  = [m.get("rxSnr")  for m in msgs if m.get("rxSnr") is not None]

    dev_series: List[dict] = []
    env_series: List[dict] = []
    pos_series: List[dict] = []
    for m in msgs:
        tel = m.get("telemetry") or {}
        ts = iso(to_utc(m.get("ts")))
        if "deviceMetrics" in tel and isinstance(tel["deviceMetrics"], dict):
            dev_series.append({"ts": ts, **tel["deviceMetrics"]})
        if "environmentMetrics" in tel and isinstance(tel["environmentMetrics"], dict):
            env_series.append({"ts": ts, **tel["environmentMetrics"]})
        pos = m.get("position")
        if isinstance(pos, dict) and pos.get("lat") is not None and pos.get("lon") is not None:
            pos_series.append({"ts": ts, "lat": pos["lat"], "lon": pos["lon"], "altitude": pos.get("altitude")})

    rq_series = [{"ts": iso(to_utc(m.get("ts"))), "rxRssi": m.get("rxRssi"), "rxSnr": m.get("rxSnr")} for m in msgs]

    nameinfo = bundle.name_map.get(node_id, {})
    return {
        "node_id": node_id,
        "name": nameinfo.get("short") or nameinfo.get("long") or node_id,
        "first_heard": iso(min(ts_list)) if ts_list else None,
        "last_heard": iso(max(ts_list)) if ts_list else None,
        "total_msgs": len(msgs),
        "median_rssi": median(rssi_vals) if rssi_vals else None,
        "median_snr":  median(snr_vals)  if snr_vals  else None,
        "telemetry_device": dev_series,
        "telemetry_env": env_series,
        "radio_quality": rq_series,
        "positions": pos_series,
    }

def build_messages(bundle: DataBundle, include_encrypted: bool, apps_filter: Optional[List[str]],
                   my_node_id: Optional[str], from_id: Optional[str], to_id: Optional[str],
                   dm_only: bool, text_contains: Optional[str], limit: int) -> dict:
    def infer_is_dm(decoded_private, decoded_dm, to_id, my_node_id):
        if decoded_private is True or decoded_dm is True:
            return True
        if my_node_id and to_id:
            return to_id.upper() == my_node_id.upper()
        return False

    msgs = bundle.messages
    if not include_encrypted:
        msgs = [m for m in msgs if not m.get("is_encrypted")]
    if apps_filter:
        apps_set = set(apps_filter)
        msgs = [m for m in msgs if m.get("app") in apps_set]
    if from_id:
        msgs = [m for m in msgs if m.get("from_id") == from_id]
    if to_id:
        msgs = [m for m in msgs if m.get("to_id") == to_id]
    if dm_only:
        msgs = [m for m in msgs if infer_is_dm(m.get("decoded_isPrivate"), m.get("decoded_dm"), m.get("to_id"), my_node_id)]
    if text_contains:
        s = text_contains.lower()
        msgs = [m for m in msgs if isinstance(m.get("text"), str) and s in m["text"].lower()]

    msgs.sort(key=lambda m: to_utc(m.get("ts")) or datetime.fromtimestamp(0, tz=timezone.utc), reverse=True)
    msgs = msgs[:max(1, min(limit, MAX_MESSAGES_RETURN))]

    def id_to_name(nid: Optional[str]) -> str:
        if not isinstance(nid, str): return ""
        info = bundle.name_map.get(nid, {})
        return info.get("short") or info.get("long") or nid

    rows = []
    for m in msgs:
        rows.append({
            "ts": m.get("ts"),
            "from_id": m.get("from_id"),
            "from_name": id_to_name(m.get("from_id")),
            "to_id": m.get("to_id"),
            "to_name": id_to_name(m.get("to_id")),
            "app": m.get("app"),
            "is_dm": (m.get("decoded_isPrivate") is True) or (m.get("decoded_dm") is True) or
                     (my_node_id and isinstance(m.get("to_id"), str) and m.get("to_id","").upper()==my_node_id.upper()),
            "channel": m.get("channel"),
            "text": m.get("text"),
            "rxRssi": m.get("rxRssi"),
            "rxSnr": m.get("rxSnr"),
            "hopLimit": m.get("hopLimit"),
            "relayNode": m.get("relayNode"),
            "id": m.get("id"),
        })
    return {"messages": rows}

# -------------------------
# HTTP Handler
# -------------------------
class Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str, code=200):
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)

        if u.path == "/":
            return self._send_html(INDEX_HTML)

        if u.path == "/api/labels":
            root = q.get("root", [DEFAULT_LOG_ROOT])[0]
            labs = list_labels(Path(root).expanduser().resolve())
            default_label = DEFAULT_LABEL if (DEFAULT_LABEL in labs) else (labs[0] if labs else "")
            return self._send_json({"labels": labs, "default": default_label})

        if u.path == "/api/overview":
            root = q.get("root", [DEFAULT_LOG_ROOT])[0]
            label = q.get("label", [""])[0]
            mode  = q.get("mode", ["hours"])[0]
            hours = int(q.get("hours", ["1"])[0])
            include_encrypted = q.get("enc", ["1"])[0] == "1"
            apps_filter = q.get("apps", [""])[0]
            apps = [a for a in apps_filter.split(",") if a] if apps_filter else None

            if not label:
                return self._send_json({"error": "missing label"}, 400)

            bundle = load_bundle(root, label, "lastfile" if mode=="lastfile" else "hours", hours)
            ov = build_overview(bundle, include_encrypted, apps)
            return self._send_json(ov)

        if u.path == "/api/node":
            root = q.get("root", [DEFAULT_LOG_ROOT])[0]
            label = q.get("label", [""])[0]
            mode  = q.get("mode", ["hours"])[0]
            hours = int(q.get("hours", ["1"])[0])
            include_encrypted = q.get("enc", ["1"])[0] == "1"
            apps_filter = q.get("apps", [""])[0]
            apps = [a for a in apps_filter.split(",") if a] if apps_filter else None
            node_id = q.get("node_id", [""])[0]

            if not label or not node_id:
                return self._send_json({"error": "missing label or node_id"}, 400)

            bundle = load_bundle(root, label, "lastfile" if mode=="lastfile" else "hours", hours)
            detail = build_node_detail(bundle, node_id, include_encrypted, apps)
            return self._send_json(detail)

        if u.path == "/api/messages":
            root = q.get("root", [DEFAULT_LOG_ROOT])[0]
            label = q.get("label", [""])[0]
            mode  = q.get("mode", ["hours"])[0]
            hours = int(q.get("hours", ["1"])[0])
            include_encrypted = q.get("enc", ["1"])[0] == "1"
            apps_filter = q.get("apps", [""])[0]
            apps = [a for a in apps_filter.split(",") if a] if apps_filter else None
            my_override = q.get("my", [""])[0] or None
            from_id = q.get("from", [""])[0] or None
            to_id   = q.get("to", [""])[0] or None
            dm_only = q.get("dm", ["0"])[0] == "1"
            text_contains = q.get("q", [""])[0] or None
            limit = int(q.get("limit", ["1000"])[0])

            if not label:
                return self._send_json({"error": "missing label"}, 400)

            bundle = load_bundle(root, label, "lastfile" if mode=="lastfile" else "hours", hours)
            my_node_id = my_override or bundle.my_node_id
            resp = build_messages(bundle, include_encrypted, apps, my_node_id, from_id, to_id, dm_only, text_contains, limit)
            resp["from_ids"] = sorted({m.get("from_id") for m in bundle.messages if m.get("from_id")})
            resp["to_ids"]   = sorted({m.get("to_id") for m in bundle.messages if m.get("to_id")})
            resp["apps_available"] = sorted(list(bundle.app_set))
            resp["my_node_id"] = my_node_id
            return self._send_json(resp)

        self.send_response(404)
        self.end_headers()

# -------------------------
# HTML / JS (frontend)
# -------------------------
INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Meshtastic WebUI (Standalone v1.2)</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<link rel="preconnect" href="https://cdn.jsdelivr.net"/>
<link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin/>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin=""/>
<style>
:root { --bg:#0b1320; --panel:#111827; --muted:#6b7280; --text:#e5e7eb; --accent:#60a5fa; }
* { box-sizing:border-box; }
body { margin:0; font-family: ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Ubuntu; background:var(--bg); color:var(--text);}
header{ padding:12px 16px; border-bottom:1px solid #1f2937; display:flex; gap:12px; align-items:center; position:sticky; top:0; background:rgba(11,19,32,.9); backdrop-filter: blur(4px); }
h1{ font-size:18px; margin:0 12px 0 0; }
small{ color:var(--muted); }
.container{ display:flex; gap:16px; padding:16px; }
.sidebar{ width:320px; background:var(--panel); padding:12px; border-radius:10px; height: calc(100vh - 80px); overflow:auto; position:sticky; top:70px;}
.main{ flex:1; display:flex; flex-direction:column; gap:16px;}
.card{ background:var(--panel); border-radius:10px; padding:12px; }
.row{ display:flex; gap:12px; }
label{ font-size:12px; color:#9ca3af; display:block; margin-bottom:4px;}
input[type=text], select, input[type=number]{ width:100%; padding:8px; border-radius:8px; background:#0f172a; border:1px solid #1f2937; color:var(--text);}
.checkbox{ display:flex; align-items:center; gap:8px; margin:8px 0;}
button{ background:var(--accent); color:#0b1320; border:none; padding:10px 12px; border-radius:8px; font-weight:600; cursor:pointer;}
button:disabled{ opacity:.6; cursor:not-allowed;}
table{ width:100%; border-collapse: collapse; }
th, td{ padding:8px 6px; border-bottom:1px solid #1f2937; font-size:13px;}
th{ text-align:left; color:#93c5fd; cursor:pointer; user-select:none;}
th.sort-asc::after{ content:" ▲"; }
th.sort-desc::after{ content:" ▼"; }
.kpi{ font-weight:700; }
.note{ color:var(--muted); font-size:12px; }
.tabbar{ display:flex; gap:8px; }
.tabbar button{ background:#0f172a; color:#cbd5e1; }
.tabbar button.active{ background:var(--accent); color:#0b1320; }
.badge{ background:#0f172a; padding:2px 6px; border-radius:6px; margin:0 4px; font-size:12px; color:#a5b4fc;}
#map_node{ height:320px; border-radius:10px; }
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin=""></script>
</head>
<body>
<header>
  <h1>📡 Meshtastic WebUI</h1>
  <small>Standalone v1.2 — LAN bind, sortable messages, local time, GPS map</small>
</header>
<div class="container">
  <div class="sidebar">
    <div class="card">
      <label>Logs root</label>
      <input id="root" type="text" value="./meshtastic_logs" />
      <label style="margin-top:8px;">Label (subfolder)</label>
      <select id="label"></select>
      <div class="row">
        <div style="flex:1">
          <label>Lookback mode</label>
          <select id="mode">
            <option value="hours">Last N hours</option>
            <option value="lastfile">Last log file</option>
          </select>
        </div>
        <div style="flex:1">
          <label>Hours</label>
          <input id="hours" type="number" min="1" max="168" value="1"/>
        </div>
      </div>
      <div class="checkbox"><input id="enc" type="checkbox" checked/> <span>Include encrypted</span></div>
      <label>App filters (comma list)</label>
      <input id="apps" type="text" placeholder="e.g. TEXT_MESSAGE_APP,TELEMETRY_APP"/>
      <div style="display:flex; gap:8px; margin-top:10px;">
        <button id="apply">Apply</button>
        <button id="refresh">↻ Refresh</button>
      </div>
      <div style="margin-top:8px;" class="note" id="fileinfo"></div>
    </div>
    <div class="card">
      <div class="note">Tip: Click a column header in Overview or Messages to sort. Times show in your local timezone.</div>
    </div>
  </div>
  <div class="main">
    <div class="tabbar">
      <button data-tab="overview" class="active">Overview</button>
      <button data-tab="node">Node Detail</button>
      <button data-tab="messages">Messages</button>
    </div>

    <div id="view-overview" class="card"></div>
    <div id="view-node" class="card" style="display:none;"></div>
    <div id="view-messages" class="card" style="display:none;"></div>
  </div>
</div>

<script>
const qs = (s)=>document.querySelector(s);
const qsa = (s)=>Array.from(document.querySelectorAll(s));
const c2f = (c)=> (c==null? null : (c*9/5)+32);
const toLocal = (iso)=>{ try{ return new Date(iso).toLocaleString(); }catch(e){ return iso||""; } };

qsa(".tabbar button").forEach(btn=>{
  btn.onclick=()=>{
    qsa(".tabbar button").forEach(b=>b.classList.remove("active"));
    btn.classList.add("active");
    const tab = btn.dataset.tab;
    ["overview","node","messages"].forEach(t=>{
      qs("#view-"+t).style.display = (t===tab)?"block":"none";
    });
    if (tab==="overview") loadOverview();
    if (tab==="messages") loadMessages();
  };
});

async function loadLabels() {
  const root = qs("#root").value;
  const r = await fetch(`/api/labels?root=${encodeURIComponent(root)}`);
  const j = await r.json();
  const sel = qs("#label");
  sel.innerHTML = "";
  (j.labels||[]).forEach(l=>{
    const o = document.createElement("option");
    o.value=l; o.textContent=l;
    sel.appendChild(o);
  });
  if (j.default) sel.value = j.default;
}

function uiParams(extra={}) {
  const p = new URLSearchParams();
  p.set("root", qs("#root").value);
  p.set("label", qs("#label").value);
  p.set("mode", qs("#mode").value);
  p.set("hours", qs("#hours").value || "1");
  p.set("enc", qs("#enc").checked ? "1":"0");
  const apps = (qs("#apps").value||"").split(",").map(s=>s.trim()).filter(Boolean);
  if (apps.length) p.set("apps", apps.join(","));
  for (const [k,v] of Object.entries(extra)) p.set(k, v);
  return p.toString();
}

function fmt(v) { return (v===null || v===undefined || v==="") ? "—" : v; }
function fmtNum(v, d=2) { return (v===null || v===undefined) ? "—" : Number(v).toFixed(d); }

let overviewState = { sortKey:"last_heard", sortAsc:false, search:"" };

function sortRows(rows, key, asc){
  const val = (r)=>{
    switch(key){
      case "name": return r.name?.toLowerCase()||"";
      case "node_id": return r.node_id?.toLowerCase()||"";
      case "first_heard": return r.first_heard||"";
      case "last_heard": return r.last_heard||"";
      case "total_msgs": return r.total_msgs||0;
      case "median_rssi": return r.median_rssi ?? -1e9;
      case "median_snr": return r.median_snr ?? -1e9;
      case "text": return (r.app_counts?.["TEXT_MESSAGE_APP"]||0);
      case "telem": return (r.app_counts?.["TELEMETRY_APP"]||0);
      case "pos": return (r.app_counts?.["POSITION_APP"]||0);
      case "battery": return r.device?.batteryLevel ?? -1e9;
      case "voltage": return r.device?.voltage ?? -1e9;
      case "tempF": return (r.environment?.temperature!=null ? c2f(r.environment.temperature) : -1e9);
      case "humid": return r.environment?.relativeHumidity ?? -1e9;
      case "iaq": return r.environment?.iaq ?? -1e9;
      default: return r.last_heard||"";
    }
  };
  rows.sort((a,b)=>{
    const va = val(a), vb = val(b);
    if (va<vb) return asc? -1: 1;
    if (va>vb) return asc? 1: -1;
    return 0;
  });
}

function passesSearch(r, needle){
  if (!needle) return true;
  const s = needle.toLowerCase();
  return (r.name?.toLowerCase().includes(s)) || (r.node_id?.toLowerCase().includes(s));
}

function renderOverviewTable(j){
  const el = qs("#view-overview");
  const appsList = (j.apps_available||[]).join(", ")||"—";
  qs("#fileinfo").textContent = `Loaded ${j.files_loaded?.length||0} file(s). Apps: ${appsList}`;

  let html = `
  <div class="row" style="align-items:flex-end;">
    <div style="flex:1">
      <h2 style="margin:6px 0;">Nodes</h2>
    </div>
    <div style="flex:1">
      <label>Search (name or node ID)</label>
      <input id="ovsearch" type="text" placeholder="Type to filter..." value="${overviewState.search||""}"/>
    </div>
  </div>`;

  html += `<table><thead><tr>
    <th data-k="name">Name</th>
    <th data-k="node_id">Node ID</th>
    <th data-k="first_heard">First Heard</th>
    <th data-k="last_heard">Last Heard</th>
    <th data-k="total_msgs">Total</th>
    <th data-k="median_rssi">Median RSSI</th>
    <th data-k="median_snr">Median SNR</th>
    <th data-k="text">TEXT</th>
    <th data-k="telem">TELEM</th>
    <th data-k="pos">POS</th>
    <th data-k="battery">Battery %</th>
    <th data-k="voltage">Voltage</th>
    <th data-k="tempF">Temp °F</th>
    <th data-k="humid">Humidity %</th>
    <th data-k="iaq">IAQ</th>
  </tr></thead><tbody id="ovbody">`;

  let rows = (j.nodes||[]).filter(r=>passesSearch(r, overviewState.search));
  sortRows(rows, overviewState.sortKey, overviewState.sortAsc);

  for (const n of rows) {
    const ac = n.app_counts||{};
    const dev = n.device||{};
    const env = n.environment||{};
    const tempF = (env.temperature!=null)? (c2f(env.temperature)) : null;

    html += `<tr class="node-row" data-node="${n.node_id}">
      <td>${fmt(n.name)}</td>
      <td><code>${fmt(n.node_id)}</code></td>
      <td>${n.first_heard? toLocal(n.first_heard): "—"}</td>
      <td>${n.last_heard? toLocal(n.last_heard): "—"}</td>
      <td>${fmt(n.total_msgs)}</td>
      <td>${fmtNum(n.median_rssi,0)}</td>
      <td>${fmtNum(n.median_snr,2)}</td>
      <td>${fmt(ac["TEXT_MESSAGE_APP"]||0)}</td>
      <td>${fmt(ac["TELEMETRY_APP"]||0)}</td>
      <td>${fmt(ac["POSITION_APP"]||0)}</td>
      <td>${fmt(dev.batteryLevel)}</td>
      <td>${fmt(dev.voltage)}</td>
      <td>${fmtNum(tempF,1)}</td>
      <td>${fmt(env.relativeHumidity)}</td>
      <td>${fmt(env.iaq)}</td>
    </tr>`;
  }
  html += `</tbody></table>
  <div class="note">Counts reflect packets this machine observed in the selected window.</div>`;

  el.innerHTML = html;

  // sort indicators
  qsa("#view-overview th").forEach(th=>{
    th.classList.remove("sort-asc","sort-desc");
    if (th.dataset.k === overviewState.sortKey) {
      th.classList.add(overviewState.sortAsc? "sort-asc":"sort-desc");
    }
  });

  // header sorting
  qsa("#view-overview th").forEach(th=>{
    th.onclick = ()=>{
      const k = th.dataset.k;
      if (!k) return;
      if (overviewState.sortKey === k) {
        overviewState.sortAsc = !overviewState.sortAsc;
      } else {
        overviewState.sortKey = k;
        overviewState.sortAsc = (k==="name" || k==="node_id" || k==="first_heard") ? true : false;
      }
      renderOverviewTable(j);
    };
  });

  // drilldown
  qsa(".node-row").forEach(tr=>{
    tr.onclick=()=>{
      qsa(".tabbar button").forEach(b=>b.classList.remove("active"));
      qsa('.tabbar button[data-tab="node"]')[0].classList.add("active");
      ["overview","node","messages"].forEach(t=>{
        qs("#view-"+t).style.display = (t==="node")?"block":"none";
      });
      loadNode(tr.dataset.node);
    };
  });

  qs("#ovsearch").oninput = (e)=>{
    overviewState.search = e.target.value || "";
    renderOverviewTable(j);
  };
}

async function loadOverview() {
  const r = await fetch(`/api/overview?`+uiParams());
  const j = await r.json();
  if (j.error) {
    qs("#view-overview").innerHTML = `<div class="note">${j.error}</div>`;
    return;
  }
  renderOverviewTable(j);
}

let charts = {};
function destroyChart(id){ if (charts[id]){ charts[id].destroy(); delete charts[id]; } }
let maps = {};

function lineChart(id, datasets, labels){
  destroyChart(id);
  const ctx = document.getElementById(id).getContext('2d');
  charts[id] = new Chart(ctx, {
    type: 'line',
    data: { labels, datasets },
    options: {
      responsive:true,
      scales:{ x:{ ticks:{ color:'#cbd5e1'} }, y:{ ticks:{ color:'#cbd5e1' } } },
      plugins:{ legend:{ labels:{ color:'#cbd5e1' } } }
    }
  });
}

function initMap(id, points){
  if (maps[id]) { maps[id].remove(); delete maps[id]; }
  const m = L.map(id);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 19, attribution: '&copy; OpenStreetMap'
  }).addTo(m);
  const latlngs = points.map(p=>[p.lat, p.lon]);
  if (latlngs.length===1){
    const marker = L.marker(latlngs[0]).addTo(m);
    m.setView(latlngs[0], 14);
  } else {
    L.polyline(latlngs, {color:'#60a5fa'}).addTo(m);
    latlngs.forEach(ll=>L.circleMarker(ll,{radius:3,color:'#a5b4fc'}).addTo(m));
    const b = L.latLngBounds(latlngs);
    m.fitBounds(b, {padding:[20,20]});
  }
  maps[id] = m;
}

async function loadNode(node_id) {
  const r = await fetch(`/api/node?`+uiParams({node_id}));
  const j = await r.json();
  const el = qs("#view-node");
  if (j.error) { el.innerHTML = `<div class="note">${j.error}</div>`; return; }

  let html = `<h2>Node Detail</h2>
  <div class="row">
    <div class="card" style="flex:1">
      <div class="kpi">${j.name}</div>
      <div><code>${j.node_id}</code></div>
    </div>
    <div class="card" style="flex:1">
      <div>First Heard: <b>${j.first_heard? toLocal(j.first_heard): "—"}</b></div>
      <div>Last Heard: <b>${j.last_heard? toLocal(j.last_heard): "—"}</b></div>
    </div>
    <div class="card" style="flex:1">
      <div>Total Messages: <b>${fmt(j.total_msgs)}</b></div>
      <div>Median RSSI/SNR: <b>${fmtNum(j.median_rssi,0)} dBm / ${fmtNum(j.median_snr,2)} dB</b></div>
    </div>
  </div>

  <h3>Radio Quality Observed Here</h3>
  <div class="card"><canvas id="chart_radio" height="160"></canvas></div>

  <h3>Telemetry</h3>
  <div class="row">
    <div class="card" style="flex:1"><canvas id="chart_dev1" height="140"></canvas></div>
    <div class="card" style="flex:1"><canvas id="chart_env1" height="140"></canvas></div>
  </div>
  <div class="row">
    <div class="card" style="flex:1"><canvas id="chart_dev2" height="140"></canvas></div>
    <div class="card" style="flex:1"><canvas id="chart_env2" height="140"></canvas></div>
  </div>`;

  // If GPS positions exist, show map under telemetry
  const pos = (j.positions||[]);
  if (pos.length>0){
    html += `
    <h3>GPS Track</h3>
    <div id="map_node" class="card"></div>`;
  }
  el.innerHTML = html;

  const dev = j.telemetry_device||[];
  const env = j.telemetry_env||[];
  const rq  = j.radio_quality||[];
  const ts_dev = dev.map(d=> d.ts? toLocal(d.ts): "");
  const ts_env = env.map(d=> d.ts? toLocal(d.ts): "");
  const ts_rq  = rq.map(d=> d.ts? toLocal(d.ts): "");

  // Radio chart (local time)
  lineChart("chart_radio", [
    {label:"RSSI (dBm)", data: rq.map(d=>d.rxRssi??null), borderColor:"#22d3ee"},
    {label:"SNR (dB)", data: rq.map(d=>d.rxSnr??null), borderColor:"#eab308"}
  ], ts_rq);

  // Telemetry (°F for temp, local time labels)
  lineChart("chart_dev1", [
    {label:"Voltage (V)", data: dev.map(d=>d.voltage??null), borderColor:"#60a5fa"},
    {label:"Battery %", data: dev.map(d=>d.batteryLevel??null), borderColor:"#10b981"}
  ], ts_dev);

  lineChart("chart_env1", [
    {label:"Temp °F", data: env.map(d=> d.temperature!=null? c2f(d.temperature): null), borderColor:"#f59e0b"},
    {label:"Humidity %", data: env.map(d=>d.relativeHumidity??null), borderColor:"#34d399"}
  ], ts_env);

  lineChart("chart_dev2", [
    {label:"Channel Util", data: dev.map(d=>d.channelUtilization??null), borderColor:"#a78bfa"},
    {label:"AirUtilTx", data: dev.map(d=>d.airUtilTx??null), borderColor:"#f472b6"}
  ], ts_dev);

  lineChart("chart_env2", [
    {label:"Pressure hPa", data: env.map(d=>d.barometricPressure??null), borderColor:"#93c5fd"},
    {label:"IAQ", data: env.map(d=>d.iaq??null), borderColor:"#fb7185"}
  ], ts_env);

  // Map
  if (pos.length>0){
    // slight delay to ensure #map_node has layout
    setTimeout(()=> initMap("map_node", pos), 50);
  }
}

// -------- Messages (sortable) ----------
let messagesState = { rows:[], sortKey:"ts", sortAsc:false, lastQuery:null };

function sortMessages(rows, key, asc){
  const get = (r)=>{
    switch(key){
      case "ts": return r.ts || "";
      case "from": return (r.from_name||"")+ (r.from_id||"");
      case "to": return (r.to_name||"")+ (r.to_id||"");
      case "app": return r.app||"";
      case "dm": return r.is_dm? 1: 0;
      case "chan": return r.channel ?? -1e9;
      case "text": return r.text||"";
      case "rssi": return r.rxRssi ?? -1e9;
      case "snr": return r.rxSnr ?? -1e9;
      case "hop": return r.hopLimit ?? -1e9;
      case "relay": return r.relayNode ?? "";
      case "id": return r.id || "";
      default: return r.ts || "";
    }
  };
  rows.sort((a,b)=>{
    const va=get(a), vb=get(b);
    if (va<vb) return asc? -1: 1;
    if (va>vb) return asc? 1: -1;
    return 0;
  });
}

async function loadMessages() {
  const params = uiParams({limit:"1000"});
  messagesState.lastQuery = params;
  const r = await fetch(`/api/messages?`+params);
  const j = await r.json();
  const el = qs("#view-messages");
  const fromOpts = (j.from_ids||[]).map(v=>`<option value="${v}">${v}</option>`).join("");
  const toOpts   = (j.to_ids||[]).map(v=>`<option value="${v}">${v}</option>`).join("");
  const apps = (j.apps_available||[]).join(",");

  let html = `<div class="row">
    <div style="flex:1"><label>From</label><select id="mf">${fromOpts?('<option value="">(any)</option>'+fromOpts):'<option value="">(any)</option>'}</select></div>
    <div style="flex:1"><label>To</label><select id="mt">${toOpts?('<option value="">(any)</option>'+toOpts):'<option value="">(any)</option>'}</select></div>
    <div style="flex:1"><label>Text contains</label><input id="mq" type="text"/></div>
    <div style="flex:.6"><label>&nbsp;</label><div class="checkbox"><input id="mdm" type="checkbox"/> <span>DMs only</span></div></div>
    <div style="flex:.5"><label>&nbsp;</label><button id="mapply">Apply</button></div>
  </div>
  <div class="note" style="margin:6px 0;">Apps available: ${apps || "—"}</div>
  <table><thead><tr>
    <th data-k="ts">Time (Local)</th>
    <th data-k="from">From</th>
    <th data-k="to">To</th>
    <th data-k="app">App</th>
    <th data-k="dm">DM</th>
    <th data-k="chan">Chan</th>
    <th data-k="text">Text</th>
    <th data-k="rssi">RSSI</th>
    <th data-k="snr">SNR</th>
    <th data-k="hop">Hop</th>
    <th data-k="relay">Relay</th>
    <th data-k="id">ID</th>
  </tr></thead><tbody id="mtbody"></tbody></table>
  <div class="note">Showing up to 1000 most recent rows. Click headers to sort.</div>`;
  el.innerHTML = html;

  messagesState.rows = (j.messages||[]);

  function renderMsgs(){
    const body = qs("#mtbody"); body.innerHTML = "";
    const rows = messagesState.rows.slice();
    sortMessages(rows, messagesState.sortKey, messagesState.sortAsc);
    rows.forEach(m=>{
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${m.ts? toLocal(m.ts): ""}</td>
      <td>${m.from_name? (m.from_name+" <span class='badge'>"+m.from_id+"</span>") : ("<code>"+(m.from_id||"")+"</code>")}</td>
      <td>${m.to_name? (m.to_name+" <span class='badge'>"+m.to_id+"</span>") : ("<code>"+(m.to_id||"")+"</code>")}</td>
      <td>${m.app||""}</td>
      <td>${m.is_dm? "✅":""}</td>
      <td>${m.channel??""}</td>
      <td>${m.text??""}</td>
      <td>${m.rxRssi??""}</td>
      <td>${m.rxSnr??""}</td>
      <td>${m.hopLimit??""}</td>
      <td>${m.relayNode??""}</td>
      <td>${m.id??""}</td>`;
      body.appendChild(tr);
    });

    // header sort indicators
    qsa("#view-messages th").forEach(th=>{
      th.classList.remove("sort-asc","sort-desc");
      if (th.dataset.k === messagesState.sortKey) {
        th.classList.add(messagesState.sortAsc? "sort-asc":"sort-desc");
      }
    });
  }
  renderMsgs();

  // clickable headers
  qsa("#view-messages th").forEach(th=>{
    th.onclick = ()=>{
      const k = th.dataset.k; if (!k) return;
      if (messagesState.sortKey === k) {
        messagesState.sortAsc = !messagesState.sortAsc;
      } else {
        messagesState.sortKey = k;
        messagesState.sortAsc = (k==="from" || k==="to" || k==="app" || k==="text") ? true : false;
      }
      renderMsgs();
    };
  });

  // Filters
  qs("#mapply").onclick = async ()=>{
    const extra = {
      from: qs("#mf").value||"",
      to: qs("#mt").value||"",
      dm: qs("#mdm").checked ? "1":"0",
      q: qs("#mq").value||"",
      limit: "1000"
    };
    const r2 = await fetch(`/api/messages?`+uiParams(extra));
    const j2 = await r2.json();
    messagesState.rows = (j2.messages||[]);
    renderMsgs();
  };
}

qs("#apply").onclick = ()=>{ loadOverview(); };
qs("#refresh").onclick = ()=>{ loadOverview(); };

(async function init(){
  await loadLabels();
  loadOverview();
})();
</script>
</body>
</html>
"""

# -------------------------
# Main
# -------------------------
def main():
    httpd = HTTPServer((HOST, PORT), Handler)
    print(f"Meshtastic WebUI (Standalone v1.2) -> http://{HOST}:{PORT}")
    print(f"Logs root default: {DEFAULT_LOG_ROOT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

if __name__ == "__main__":
    main()
