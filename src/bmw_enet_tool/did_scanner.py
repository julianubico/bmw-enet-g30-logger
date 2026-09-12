"""DID scanner: discover supported Data Identifiers on an ECU (read-only).

The scanner probes candidate DIDs with UDS 0x22 (read) and 0x2C
(define/clear dynamic DID) — the only two services on the hard allowlist.
Any attempt to build a request for another service (0x2E write, 0x31
routine, 0x11 reset, 0x27 security access, ...) raises ValueError before
anything touches the wire.

Per (DID, size) probe:
  1. define dynamic DID 0xF300 = <DID> via 0x2C (sizes 1, 2 and 4);
  2. if the define succeeds, read it 5x via 0x22 F3 00;
  3. always clear the dynamic DID again with 0x2C (incl. on cancel);
  4. if the define is rejected with NRC 0x12 or 0x31 (dynamic DID not
     supported), fall back to plain 0x22 <DID> reads.

The transport layer skips gateway echo frames (HSFZ type 0x0002) and any
frame whose source ECU is not the one being probed, and it reassembles
fragmented / concatenated TCP segments before matching responses.

Reports are plain JSON-serialisable dicts; export_report() writes them to
disk and apply_discovery() copies a positive result into the live sensor
registry as candidate/unverified — the built-in profile templates are
never mutated.
"""

import json
import logging
import re
import socket
import time
from datetime import datetime, timezone

from .protocol import TESTER, DYN_H, DYN_L, hsfz, parse_hsfz

log = logging.getLogger(__name__)

#: The only UDS services the scanner may ever send.  Everything else —
#: 0x2E (write), 0x31 (routine), 0x11 (reset), 0x27 (security access),
#: 0x2F (I/O control), 0x34/0x36/0x37 (flashing) — is refused outright.
ALLOWED_SERVICES = (0x22, 0x2C)

#: Payload widths probed per DID.
PROBE_SIZES = (1, 2, 4)

#: NRCs on a 0x2C define that mean "dynamic DIDs unsupported here":
#: 0x12 subFunctionNotSupported, 0x31 requestOutOfRange.
NRC_DIRECT_FALLBACK = (0x12, 0x31)

#: 0x78 = response pending: keep waiting for the real answer.
NRC_RESPONSE_PENDING = 0x78

#: Repeat samples per (DID, size) to confirm the value is live, not stale.
SAMPLES_PER_DID = 5


def guard_service(uds):
    """Refuse any UDS payload whose service is not on the read-only allowlist."""
    if not uds:
        raise ValueError("empty UDS payload")
    svc = uds[0]
    if svc not in ALLOWED_SERVICES:
        raise ValueError(
            f"UDS service 0x{svc:02X} is not in the read-only allowlist "
            f"({', '.join(f'0x{s:02X}' for s in ALLOWED_SERVICES)}) — refused"
        )
    return uds


#: Maximum DIDs a single a-b range token may expand to (safety cap).
MAX_RANGE_SPAN = 4096


def _parse_token(token):
    """Parse one DID token: plain hex ("1234"/"0x1234") or a hex range
    ("1000-10FF", endpoints inclusive).  Returns a list of ints."""
    if "-" in token[1:]:  # a range; a leading "-" stays a negative number
        parts = token.split("-")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError(f"not a hex DID or range: {token!r}")
        try:
            start = int(parts[0], 16)
            end = int(parts[1], 16)
        except ValueError:
            raise ValueError(f"not a hex DID or range: {token!r}")
        if not (0x0001 <= start <= 0xFFFF) or not (0x0001 <= end <= 0xFFFF):
            raise ValueError(f"DID range out of bounds: {token!r}")
        if end < start:
            raise ValueError(f"reversed DID range: {token!r}")
        if end - start >= MAX_RANGE_SPAN:
            raise ValueError(
                f"DID range too large (max {MAX_RANGE_SPAN}): {token!r}")
        return list(range(start, end + 1))
    try:
        did = int(token, 16)
    except ValueError:
        raise ValueError(f"not a hex DID: {token!r}")
    if not 0x0001 <= did <= 0xFFFF:
        raise ValueError(f"DID out of range (0x0001..0xFFFF): {token!r}")
    return [did]


def parse_candidates(*args):
    """Parse user-supplied DID candidates into a deduped list of ints.

    Accepts "1234", "0x1234", ranges like "1000-10FF", comma/space/
    semicolon separated groups and multiple group arguments.  Raises
    ValueError on anything that is not a 0x0001..0xFFFF hex DID or a sane
    range — empty strings, empty groups, negatives, reversed ranges.
    """
    dids = []
    for arg in args:
        text = arg.strip() if isinstance(arg, str) else ""
        if not text:
            raise ValueError("empty candidate group")
        for token in re.split(r"[,\s;]+", text):
            if not token:
                raise ValueError("empty DID token")
            for did in _parse_token(token):
                if did not in dids:
                    dids.append(did)
    if not dids:
        raise ValueError("no candidate DIDs")
    return dids


class ScannerTransport:
    """Request/response over an HSFZ socket with gateway-echo filtering.

    request() sends one guarded UDS request and waits for the matching
    positive response from the probed ECU.  Returns (kind, detail):
      ("data", uds)    — positive response (uds includes service byte),
      ("nrc", code)    — negative response,
      ("timeout", nrc) — no answer before the deadline (nrc is the last
                         pending code seen, e.g. 0x78, or None).
    """

    def __init__(self, sock, stop_event=None, timeout=2.0):
        self.sock = sock
        self.stop_event = stop_event
        self.timeout = timeout
        self._rx = b""

    def _send(self, ecu, uds):
        self.sock.sendall(hsfz(TESTER, ecu, guard_service(uds)))

    def request(self, ecu, uds, expect):
        guard_service(uds)
        self._send(ecu, uds)
        deadline = time.monotonic() + self.timeout
        pending_nrc = None
        self.sock.settimeout(max(0.01, self.timeout))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ("timeout", pending_nrc)
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                if pending_nrc == NRC_RESPONSE_PENDING:
                    continue  # ECU is still working — keep waiting
                return ("timeout", pending_nrc)
            except OSError:
                return ("timeout", pending_nrc)
            if not chunk:
                return ("timeout", pending_nrc)
            self._rx += chunk
            while True:
                res = parse_hsfz(self._rx)
                if res is None:
                    break  # need more bytes (fragmented frame)
                src, _dst, rud, consumed, msg_type = res
                self._rx = self._rx[consumed:]
                if msg_type != 0x0001:
                    continue  # gateway echo / ack — never data
                if src != ecu:
                    continue  # answer for somebody else's question
                if rud[:len(expect)] == expect:
                    return ("data", rud)
                if rud and rud[0] == 0x7F and len(rud) >= 3:
                    code = rud[2]
                    if code == NRC_RESPONSE_PENDING:
                        pending_nrc = code
                        continue
                    return ("nrc", code)
                # Unrelated positive response — ignore, keep listening.


class DIDScanner:
    """Probe candidate DIDs on one ECU and build a JSON report."""

    def __init__(self, transport, sample_interval=0.0,
                 samples_per_did=SAMPLES_PER_DID):
        self.transport = transport
        self.sample_interval = sample_interval
        self.n_samples = samples_per_did

    def _stopped(self):
        ev = getattr(self.transport, "stop_event", None)
        return ev is not None and ev.is_set()

    # ── public ──────────────────────────────────────────────
    def scan(self, ecu, dids):
        report = {
            "ecu": ecu,
            "ecu_hex": f"0x{ecu:02X}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verified": False,
            "stopped": False,
            "dids_scanned": list(dids),
            "results": [],
        }
        for did in dids:
            if self._stopped():
                report["stopped"] = True
                break
            for size in PROBE_SIZES:
                if self._stopped():
                    break
                result = self._probe(ecu, did, size)
                report["results"].append(result)
                if result.get("cancelled"):
                    report["stopped"] = True
                    break
            if report["stopped"]:
                break
        return report

    # ── one (DID, size) probe ───────────────────────────────
    def _probe(self, ecu, did, size):
        dh, dl = (did >> 8) & 0xFF, did & 0xFF
        result = {
            "did": did,
            "did_hex": f"0x{did:04X}",
            "size": size,
            "payload_length": size,
            "read_mode": "dynamic",
            "status": "unknown",
            "nrc": None,
            "define": {"status": "unknown", "nrc": None},
            "samples": [],
            "raw_min": None,
            "raw_max": None,
            "clear": {"status": "not_attempted", "nrc": None},
            "timing_ms": 0.0,
            "hint": "",
            "cancelled": False,
        }
        t0 = time.monotonic()
        kind, detail = self.transport.request(
            ecu,
            bytes([0x2C, 0x01, DYN_H, DYN_L, dh, dl, 0x01, size]),
            bytes([0x6C, 0x01, DYN_H, DYN_L]),
        )
        if kind == "data":
            result["define"] = {"status": "positive", "nrc": None}
            self._sample_dynamic(ecu, size, result)
            # Always release the dynamic DID — success, timeout or cancel.
            result["clear"] = self._clear(ecu)
        elif kind == "nrc" and detail in NRC_DIRECT_FALLBACK:
            result["define"] = {"status": "nrc", "nrc": detail}
            result["read_mode"] = "direct"
            self._sample_direct(ecu, did, result)
        elif kind == "nrc":
            result["define"] = {"status": "nrc", "nrc": detail}
            result["status"] = "nrc"
            result["nrc"] = detail
        else:
            result["define"] = {"status": "timeout", "nrc": detail}
            result["status"] = "timeout"
            result["nrc"] = detail
        result["timing_ms"] = round((time.monotonic() - t0) * 1000, 1)
        result["hint"] = self._hint(did, size, result)
        return result

    def _sample_dynamic(self, ecu, size, result):
        raws = []
        for _ in range(self.n_samples):
            if self._stopped():
                result["cancelled"] = True
                result["status"] = "cancelled"
                return
            t = time.monotonic()
            kind, detail = self.transport.request(
                ecu, bytes([0x22, DYN_H, DYN_L]),
                bytes([0x62, DYN_H, DYN_L]),
            )
            ms = round((time.monotonic() - t) * 1000, 1)
            if kind == "data":
                payload = detail[3:3 + size]
                raw = int.from_bytes(payload, "big") if payload else None
                result["samples"].append(
                    {"status": "positive", "nrc": None, "raw": raw,
                     "timing_ms": ms})
                if raw is not None:
                    raws.append(raw)
            elif kind == "nrc":
                result["samples"].append(
                    {"status": "nrc", "nrc": detail, "raw": None,
                     "timing_ms": ms})
            else:
                result["samples"].append(
                    {"status": "timeout", "nrc": detail, "raw": None,
                     "timing_ms": ms})
            if self.sample_interval:
                time.sleep(self.sample_interval)
        self._summarise(result, raws)

    def _sample_direct(self, ecu, did, result):
        dh, dl = (did >> 8) & 0xFF, did & 0xFF
        raws = []
        for _ in range(self.n_samples):
            if self._stopped():
                result["cancelled"] = True
                result["status"] = "cancelled"
                return
            t = time.monotonic()
            kind, detail = self.transport.request(
                ecu, bytes([0x22, dh, dl]), bytes([0x62, dh, dl]))
            ms = round((time.monotonic() - t) * 1000, 1)
            if kind == "data":
                payload = detail[3:]
                result["payload_length"] = len(payload)
                raw = int.from_bytes(payload, "big") if payload else None
                result["samples"].append(
                    {"status": "positive", "nrc": None, "raw": raw,
                     "timing_ms": ms})
                if raw is not None:
                    raws.append(raw)
            elif kind == "nrc":
                result["samples"].append(
                    {"status": "nrc", "nrc": detail, "raw": None,
                     "timing_ms": ms})
            else:
                result["samples"].append(
                    {"status": "timeout", "nrc": detail, "raw": None,
                     "timing_ms": ms})
            if self.sample_interval:
                time.sleep(self.sample_interval)
        self._summarise(result, raws)

    @staticmethod
    def _summarise(result, raws):
        if result.get("cancelled"):
            return
        if raws:
            result["status"] = "positive"
            result["raw_min"] = min(raws)
            result["raw_max"] = max(raws)
        elif any(s["status"] == "nrc" for s in result["samples"]):
            result["status"] = "nrc"
            result["nrc"] = next(
                s["nrc"] for s in result["samples"] if s["status"] == "nrc")
        else:
            result["status"] = "timeout"

    def _clear(self, ecu):
        kind, detail = self.transport.request(
            ecu, bytes([0x2C, 0x03, DYN_H, DYN_L]),
            bytes([0x6C, 0x03, DYN_H, DYN_L]),
        )
        if kind == "data":
            return {"status": "positive", "nrc": None}
        if kind == "nrc":
            return {"status": "nrc", "nrc": detail}
        return {"status": "timeout", "nrc": detail}

    @staticmethod
    def _hint(did, size, result):
        hint = (
            f"DID 0x{did:04X} ({size}B probe): positive response, "
            "meaning/scale unknown — compare against ISTA live values, "
            "then label manually."
        )
        if size == 2 and result.get("raw_max") is not None:
            hint += f" 2-byte payload looks rpm-like (raw={result['raw_max']})."
        return hint


def export_report(report, path):
    """Write a scan report to *path* as JSON.  Returns the path."""
    from pathlib import Path
    p = Path(path)
    p.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                 encoding="utf-8")
    log.info("Scan report written to %s", p)
    return str(p)


def apply_discovery(sensor_id, ecu, result, timestamp):
    """Copy a positive scan result into the *live* sensor registry.

    The sensor is marked verified=False / confidence="candidate" with
    scale 1.0 / offset 0.0 — meaning and scaling still unknown until
    validated against the car.  The built-in profile templates are never
    touched; only the live registry (sensor.json) changes.
    Returns the updated sensor dict.
    """
    from . import sensors

    if sensors.get_sensor_by_id(sensor_id) is None:
        raise ValueError(f"unknown sensor_id: {sensor_id!r}")
    updates = {
        "ecu": ecu,
        "did": result["did"],
        "size": result["payload_length"],
        "read_mode": result.get("read_mode", "dynamic"),
        "scale": 1.0,
        "offset": 0.0,
        "verified": False,
        "confidence": "candidate",
        "source": f"discovered by scanner {timestamp}",
    }
    ok, msg = sensors.update_sensor(sensor_id, updates)
    if not ok:
        raise ValueError(f"apply_discovery failed: {msg}")
    return sensors.get_sensor_by_id(sensor_id)
