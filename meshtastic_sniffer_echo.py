#!/usr/bin/env python3
"""
meshtastic_sniffer_echo_v2_1.py

Unified sniffer/echo for Meshtastic over USB **or** BLE with hourly-rotated NDJSON logs.
Same behavior/format as your USB tool, plus:
- BLE preflight: performs a quick bluetoothctl connect -> waits for ServicesResolved: yes -> disconnect,
  to avoid "Service Discovery has not been performed yet" errors.
- Identical NDJSON structure & directory layout for USB and BLE.
"""

import base64
import json
import os
import signal
import sys
import threading
import time
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# =========================
# CONFIG — EDIT THESE
# =========================
TRANSPORT = "BLE"          # "USB" or "BLE"

# USB settings
PORT = "/dev/serial/by-id/usb-RAKwireless_WisCore_RAK4631_Board_16F530B55940C4C9-if00"

# BLE settings
BLE_ADDR = "F5:B4:3E:09:66:83"   # pair/trust this first via bluetoothctl

### TO GET BLUETOOTH:
# bluetoothctl
# power on
# agent KeyboardOnly
# default-agent
# scan on
### WAIT until you see: F5:B4:3E:09:66:83  HOA_6683
# pair F5:B4:3E:09:66:83
### enter the PIN when prompted (use the fixed PIN you set; otherwise try 123456)
# trust F5:B4:3E:09:66:83
# info F5:B4:3E:09:66:83      # should show Paired: yes, Trusted: yes
# disconnect F5:B4:3E:09:66:83  # free the link for your script
# quit

# Common settings
LABEL = ""                 # if blank, auto-derived (USB: basename of by-id; BLE: ble-<MAC>)
LOG_ROOT = "/mnt/external_4tb/2025_meshtastic_burn/meshtastic_logs"
USE_UTC = True
VERBOSE = True
PRINT_JSON = True          # mirror NDJSON lines to stdout
FLUSH_EVERY_LINE = True
SNAPSHOT_EVERY_MIN = 30

# Echo controls (same behavior as your USB tool)
ECHO_ENABLED = True
ECHO_ALLOW = ["!5c47b36c"]     # [] => nobody; put the IDs you want to DM-echo
ECHO_PREFIX = "ECHO BACK: "
ECHO_TEXT_APP_ONLY = True      # only echo TEXT_MESSAGE_APP

# =========================
# INTERNALS
# =========================
try:
    from pubsub import pub
    if TRANSPORT.upper() == "BLE":
        from meshtastic.ble_interface import BLEInterface
    else:
        from meshtastic.serial_interface import SerialInterface
except Exception as e:
    print("ERROR: Install dependencies: pipx install meshtastic  (or pip install meshtastic pypubsub)", file=sys.stderr)
    raise

stop_event = threading.Event()
iface = None
ALLOW_SET = set(s.strip().upper() for s in (ECHO_ALLOW or []) if s.strip())

def now_ts() -> Tuple[str, str]:
    if USE_UTC:
        dt = datetime.now(timezone.utc)
    else:
        dt = datetime.now().astimezone()
    return dt.isoformat(), dt.strftime("%Y-%m-%d_%H")

def sanitize(s: str) -> str:
    return "".join(c for c in s if (c.isalnum() or c in ("-", "_", ".", "+", "!", "@", ":")))

def safe_to_dict(obj: Any) -> Any:
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {str(k): safe_to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [safe_to_dict(x) for x in obj]
    if isinstance(obj, (bytes, bytearray)):
        return {"__bytes_b64": base64.b64encode(bytes(obj)).decode("ascii")}
    to_dict = getattr(obj, "toDict", None)
    if callable(to_dict):
        try:
            return safe_to_dict(to_dict())
        except Exception:
            pass
    d = getattr(obj, "__dict__", None)
    if isinstance(d, dict):
        try:
            return safe_to_dict(d)
        except Exception:
            pass
    try:
        return str(obj)
    except Exception:
        return repr(obj)

class HourlyNDJSONWriter:
    def __init__(self, root: Path, label: str):
        self.root = root
        self.label = sanitize(label) if label else "meshtastic"
        self.cur_hour = None
        self.fp = None
        self.lock = threading.Lock()
        self.root.mkdir(parents=True, exist_ok=True)

    def _open_for_hour(self, hour_bucket: str):
        folder = self.root / self.label
        folder.mkdir(parents=True, exist_ok=True)
        fname = f"{self.label}_{hour_bucket}.ndjson"
        path = folder / fname
        if VERBOSE and (not path.exists()):
            print(f"[INFO] Logging to {path} ...", file=sys.stderr)
        self.fp = open(path, "a", buffering=1, encoding="utf-8")
        os.fsync(self.fp.fileno())

    def write(self, event: Dict[str, Any]):
        _, hour_bucket = now_ts()
        line = json.dumps(event, ensure_ascii=False)
        with self.lock:
            if self.cur_hour != hour_bucket or self.fp is None:
                if self.fp:
                    try:
                        self.fp.flush(); os.fsync(self.fp.fileno()); self.fp.close()
                    except Exception:
                        pass
                self.cur_hour = hour_bucket
                self._open_for_hour(hour_bucket)
            self.fp.write(line + "\n")
            if FLUSH_EVERY_LINE:
                try:
                    self.fp.flush(); os.fsync(self.fp.fileno())
                except Exception:
                    pass
        if PRINT_JSON:
            print(line, flush=True)

    def close(self):
        with self.lock:
            if self.fp:
                try:
                    self.fp.flush(); os.fsync(self.fp.fileno()); self.fp.close()
                except Exception:
                    pass
                self.fp = None

def resolve_label_from_port(devpath: str) -> str:
    try:
        p = Path(devpath)
        if p.exists():
            return sanitize(p.name)
        return sanitize(devpath)
    except Exception:
        return "meshtastic"

def resolve_label_from_ble(mac: str) -> str:
    mac = (mac or "").strip()
    if not mac:
        return "ble-unknown"
    return "ble-" + sanitize(mac.replace(":", "-"))

def get_my_ids(i) -> Dict[str, Any]:
    out = {"my_node_num": None, "my_id_str": None}
    try:
        info = i.getMyNodeInfo()
        di = safe_to_dict(info)
        out["my_node_num"] = di.get("my_node_num") or di.get("myId") or di.get("num")
        cand = (
            di.get("my_node_id")
            or di.get("myNodeId")
            or di.get("user", {}).get("id")
            or di.get("user", {}).get("longName")
        )
        if cand:
            out["my_id_str"] = str(cand)
    except Exception:
        pass
    return out

def extract_ids(packet: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    from_id = packet.get("fromId") or packet.get("from") or packet.get("from_id")
    to_id = packet.get("toId") or packet.get("to") or packet.get("to_id")
    if not from_id and isinstance(packet.get("rx"), dict):
        from_id = packet["rx"].get("fromId") or packet["rx"].get("from")
    if not to_id and isinstance(packet.get("rx"), dict):
        to_id = packet["rx"].get("toId") or packet["rx"].get("to")
    return (str(from_id) if from_id is not None else None,
            str(to_id) if to_id is not None else None)

def is_text_message(packet: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    dec = packet.get("decoded") or {}
    txt = dec.get("text") or dec.get("payload") or None
    if isinstance(txt, dict) and "__bytes_b64" in txt:
        try:
            raw = base64.b64decode(txt["__bytes_b64"])
            txt = raw.decode("utf-8", errors="ignore")
        except Exception:
            return (False, None)
    if txt and isinstance(txt, str):
        return (True, txt)
    for k in ("message", "data"):
        v = dec.get(k)
        if isinstance(v, str) and v:
            return (True, v)
    return (False, None)

def is_text_app(decoded: Dict[str, Any]) -> bool:
    pn = decoded.get("portnum", decoded.get("payloadVariant"))
    if isinstance(pn, str):
        return pn.upper() == "TEXT_MESSAGE_APP"
    if isinstance(pn, int):
        return pn == 1
    return False

def likely_direct_message(packet: Dict[str, Any], my_ids: Dict[str, Any]) -> bool:
    dec = packet.get("decoded") or {}
    if dec.get("isPrivate") is True or dec.get("dm") is True:
        return True
    _, to_id = extract_ids(packet)
    my_str = my_ids.get("my_id_str")
    if my_str and to_id and to_id.upper() == str(my_str).upper():
        return True
    my_num = my_ids.get("my_node_num")
    if my_num is not None and (dec.get("destination") == my_num or packet.get("to") == my_num):
        return True
    return False

def do_send_echo(i, dest_id: str, text: str):
    if not (ECHO_ENABLED and ALLOW_SET):
        return
    if not dest_id or not text or not text.strip():
        return
    try:
        out_text = f"{ECHO_PREFIX}{text}" if ECHO_PREFIX else text
        i.sendText(text=out_text, destinationId=dest_id, wantAck=False)
        if VERBOSE:
            print(f"[ECHO] -> {dest_id}: {out_text}", file=sys.stderr, flush=True)
    except Exception as e:
        print(f"[WARN] Echo send failed to {dest_id}: {e}", file=sys.stderr)

# ---------- SUBSCRIBERS ----------
def topic_receive(packet=None, interface=None, **kwargs):
    try:
        pkt = safe_to_dict(packet)
        WRITER.write({"type": "rx", "ts": now_ts()[0], "packet": pkt})

        decoded = pkt.get("decoded") or {}
        if ECHO_TEXT_APP_ONLY and not is_text_app(decoded):
            return
        is_text, text = is_text_message(pkt)
        if not (is_text and text and text.strip()):
            return

        from_id, _to_id = extract_ids(pkt)
        if not from_id or (ALLOW_SET and from_id.upper() not in ALLOW_SET):
            return
        if not likely_direct_message(pkt, MY_IDS):
            return
        myid = MY_IDS.get("my_id_str")
        if myid and str(from_id).upper() == str(myid).upper():
            return

        do_send_echo(interface or iface, from_id, text)
        WRITER.write({
            "type": "tx_echo",
            "ts": now_ts()[0],
            "dest": from_id,
            "text": f"{ECHO_PREFIX}{text}" if ECHO_PREFIX else text,
            "portnum": decoded.get("portnum", decoded.get("payloadVariant"))
        })
    except Exception as e:
        if VERBOSE:
            print(f"[WARN] topic_receive error: {e}", file=sys.stderr)

def on_connection_established(interface=None, **kwargs):
    if VERBOSE:
        print("[INFO] Connection established.", file=sys.stderr)
    snapshot(label="snapshot_connect")

def on_connection_lost(interface=None, **kwargs):
    if VERBOSE:
        print("[INFO] Connection lost.", file=sys.stderr)

# ---------- SNAPSHOTS ----------
def snapshot(label: str = "snapshot"):
    try:
        info = safe_to_dict(iface.getMyNodeInfo())
    except Exception:
        info = None
    try:
        nodes = safe_to_dict(getattr(iface, "nodes", {}))
    except Exception:
        nodes = None
    try:
        radio = safe_to_dict(getattr(iface, "radioConfig", None))
    except Exception:
        radio = None
    WRITER.write({"type": label, "ts": now_ts()[0], "myInfo": info, "nodes": nodes, "radioConfig": radio})

def periodic_snapshots():
    while not stop_event.is_set():
        try:
            time.sleep(max(60, SNAPSHOT_EVERY_MIN * 60))
            if stop_event.is_set():
                break
            snapshot(label="snapshot_periodic")
        except Exception:
            continue

def setup_subscriptions():
    pub.subscribe(topic_receive, "meshtastic.receive")
    pub.subscribe(on_connection_established, "meshtastic.connection.established")
    try:
        pub.subscribe(on_connection_lost, "meshtastic.connection.lost")
    except Exception:
        pass

def shutdown(_signum=None, _frame=None):
    if VERBOSE:
        print("[INFO] Shutting down...", file=sys.stderr)
    stop_event.set()
    try:
        if iface:
            iface.close()
    except Exception:
        pass
    try:
        WRITER.close()
    except Exception:
        pass
    sys.exit(0)

# ---------- BLE helpers / preflight ----------
def ble_has_controller() -> bool:
    try:
        out = subprocess.run(["bluetoothctl", "list"], capture_output=True, text=True, timeout=5)
        return "Controller" in out.stdout
    except Exception:
        return False

def ble_is_paired(mac: str) -> bool:
    try:
        out = subprocess.run(["bluetoothctl", "info", mac], capture_output=True, text=True, timeout=5)
        return "Paired: yes" in out.stdout
    except Exception:
        return False

def btctl_cmds(cmds: list[str], timeout: int = 12) -> str:
    """Run bluetoothctl non-interactively with a list of commands."""
    script = "\n".join(cmds + ["quit"]) + "\n"
    p = subprocess.run(
        ["bluetoothctl"],
        input=script,
        text=True,
        capture_output=True,
        timeout=timeout
    )
    return (p.stdout or "") + (p.stderr or "")

def ble_preflight_services_resolved(mac: str, wait_sec: int = 10) -> bool:
    """Connect -> wait for ServicesResolved: yes -> disconnect."""
    if VERBOSE:
        print(f"[BLE] Preflight connect to {mac} to resolve services…", file=sys.stderr, flush=True)
    out = btctl_cmds([f"connect {mac}", f"info {mac}"])
    if "Connection successful" not in out and "Connected: yes" not in out:
        if VERBOSE:
            print("[BLE] bluetoothctl connect did not confirm; proceeding anyway.", file=sys.stderr)
    # poll info for ServicesResolved: yes
    deadline = time.time() + wait_sec
    resolved = False
    while time.time() < deadline:
        info_out = btctl_cmds([f"info {mac}"])
        if "ServicesResolved: yes" in info_out:
            resolved = True
            break
        time.sleep(0.5)
    # always disconnect to free the link for BLEInterface
    btctl_cmds([f"disconnect {mac}"])
    time.sleep(0.5)
    if VERBOSE:
        print(f"[BLE] ServicesResolved: {'yes' if resolved else 'no'}", file=sys.stderr)
    return resolved

def main():
    # Label & writer
    if TRANSPORT.upper() == "USB":
        if not PORT or "*" in PORT:
            print("ERROR: Set an exact serial by-id path in PORT (no wildcards).", file=sys.stderr)
            sys.exit(2)
        label = LABEL.strip() or resolve_label_from_port(PORT)
    else:
        if not BLE_ADDR or ":" not in BLE_ADDR:
            print("ERROR: Set BLE_ADDR to your device MAC (e.g., AA:BB:CC:DD:EE:FF).", file=sys.stderr)
            sys.exit(2)
        label = LABEL.strip() or resolve_label_from_ble(BLE_ADDR)

    global WRITER
    WRITER = HourlyNDJSONWriter(Path(LOG_ROOT), label)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    t_snap = threading.Thread(target=periodic_snapshots, daemon=True)
    t_snap.start()

    # Connect
    try:
        global iface
        if TRANSPORT.upper() == "USB":
            if VERBOSE:
                print(f"[INFO] Connecting to {PORT} ...", file=sys.stderr, flush=True)
            iface = SerialInterface(devPath=PORT)
        else:
            if not ble_has_controller():
                print("ERROR: No Bluetooth adapter/daemon. Check `systemctl status bluetooth`.", file=sys.stderr)
                sys.exit(3)
            if not ble_is_paired(BLE_ADDR):
                print(f"ERROR: BLE device {BLE_ADDR} is not paired/trusted. Use bluetoothctl to pair+trust first.", file=sys.stderr)
                sys.exit(3)
            # Preflight services discovery to avoid "Service Discovery has not been performed yet"
            ble_preflight_services_resolved(BLE_ADDR, wait_sec=10)
            if VERBOSE:
                print(f"[INFO] Connecting over BLE to {BLE_ADDR} ...", file=sys.stderr, flush=True)
            iface = BLEInterface(BLE_ADDR)
    except Exception as e:
        print(f"ERROR: Could not open {TRANSPORT.upper()} interface: {e}", file=sys.stderr)
        sys.exit(3)

    setup_subscriptions()

    global MY_IDS
    MY_IDS = get_my_ids(iface)
    if VERBOSE:
        print(f"[INFO] Connected. MyIDs={MY_IDS}  Label={label}", file=sys.stderr, flush=True)

    snapshot(label="snapshot_start")

    try:
        while not stop_event.is_set():
            time.sleep(0.25)
    finally:
        shutdown()

if __name__ == "__main__":
    main()
