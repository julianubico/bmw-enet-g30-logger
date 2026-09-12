#!/usr/bin/env python3
"""G30 B58 + ZF8HP drive logger. UDP gateway discovery, DME+EGS, JSONL output.
Usage: python g30_drive_logger.py [output.jsonl] [duration_sec]

READ-ONLY: only UDS 0x22 (ReadDataByIdentifier) is ever sent. The send path
asserts this invariant. No writes, no resets, no adaptations, no sessions.
"""
import socket
import struct
import time
import json
import sys
import os
import math

TESTER = 0xF4
DME = 0x12
EGS = 0x18

# Validated DIDs (2026-09-12 on Julian's G30 via 169.254.126.74)
# (ecu, did_hex, name, decode_fn)
CHANNELS = [
    (0x12, "4807", "dme_rpm",         lambda b: struct.unpack(">h", b[0:2])[0] / 2),
    (0x12, "4300", "dme_coolant_raw",  lambda b: b.hex()),
    (0x12, "480B", "dme_pedal",       lambda b: struct.unpack(">h", b[0:2])[0] * 0.01220703),
    (0x12, "4600", "dme_throttle",    lambda b: struct.unpack(">h", b[0:2])[0] * 0.0078125),
    (0x12, "4506", "dme_int_flank",    lambda b: struct.unpack(">h", b[0:2])[0] * 0.02197266),
    (0x12, "4507", "dme_exh_flank",    lambda b: struct.unpack(">h", b[0:2])[0] * 0.02197266),
    (0x12, "452B", "dme_vanos_in_sp",  lambda b: struct.unpack(">h", b[0:2])[0] / 10),
    (0x12, "452E", "dme_vanos_in_act", lambda b: struct.unpack(">h", b[0:2])[0] / 10),
    (0x12, "452A", "dme_vanos_ex_sp",  lambda b: struct.unpack(">h", b[0:2])[0] / 10),
    (0x12, "452C", "dme_vanos_ex_act", lambda b: struct.unpack(">h", b[0:2])[0] / 10),
    (0x12, "581A", "dme_ivo",         lambda b: struct.unpack(">h", b[0:2])[0] * 0.015625),
    (0x12, "581C", "dme_evc",         lambda b: struct.unpack(">h", b[0:2])[0] * 0.015625),
    (0x12, "4B23", "dme_misf_cyl1",   lambda b: struct.unpack(">H", b[0:2])[0]),
    (0x12, "4B24", "dme_misf_cyl2",   lambda b: struct.unpack(">H", b[0:2])[0]),
    (0x12, "4B25", "dme_misf_cyl3",   lambda b: struct.unpack(">H", b[0:2])[0]),
    (0x12, "4B30", "dme_misf_cyl4",   lambda b: struct.unpack(">H", b[0:2])[0]),
    (0x12, "58DB", "dme_misf_total",  lambda b: struct.unpack(">H", b[0:2])[0]),
    (0x12, "58F3", "dme_lpfp_kpa",    lambda b: struct.unpack(">H", b[0:2])[0] / 10),
    (0x18, "DA2A", "egs_turbine",     lambda b: struct.unpack(">h", b[0:2])[0]),
    (0x18, "DA2A", "egs_output",      lambda b: struct.unpack(">h", b[2:4])[0]),
    (0x18, "DA2E", "egs_gear",        lambda b: b[0]),
    (0x18, "DA2E", "egs_range",       lambda b: b[1]),
    (0x18, "DA22", "egs_tcc_state",   lambda b: struct.unpack(">H", b[0:2])[0]),
    (0x18, "DA12", "egs_oil_temp",    lambda b: struct.unpack(">h", b[0:2])[0] - 48),
    (0x18, "DA34", "egs_eng_rpm",     lambda b: struct.unpack(">H", b[0:2])[0]),
]

# Minimum payload bytes each decode lambda needs (guards column-type flips)
MIN_LEN = {
    "dme_rpm": 2, "dme_coolant_raw": 1, "dme_pedal": 2, "dme_throttle": 2,
    "dme_ivo": 2, "dme_evc": 2, "dme_int_flank": 2, "dme_exh_flank": 2, "dme_vanos_in_sp": 2, "dme_vanos_in_act": 2, "dme_vanos_ex_sp": 2, "dme_vanos_ex_act": 2,
    "dme_misf_cyl1": 2, "dme_misf_cyl2": 2, "dme_misf_cyl3": 2,
    "dme_misf_cyl4": 2, "dme_misf_total": 2, "dme_lpfp_kpa": 2,
    "egs_turbine": 4, "egs_output": 4, "egs_gear": 2, "egs_range": 2,
    "egs_tcc_state": 2, "egs_oil_temp": 2, "egs_eng_rpm": 2,
}


def discover_gateway(timeout=5):
    """UDP discovery: find IP whose reply contains DIAGADR10.

    Collects all candidates through the window; refuses ambiguous results.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(("0.0.0.0", 0))
        s.sendto(bytes.fromhex("000000000011"), ("169.254.255.255", 6811))
        deadline = time.monotonic() + timeout
        cands = []
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                break
            s.settimeout(rem)
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                break
            # Basic structure: 4B len + 2B type(0x0011) + body starting DIAGADR10
            if len(data) >= 16 and data[4:6] == b"\x00\x11" and b"DIAGADR10" in data:
                if addr[0] not in [c[0] for c in cands]:
                    cands.append((addr[0], data[:48].hex().upper()))
    finally:
        s.close()
    if len(cands) == 1:
        return cands[0][0]
    if not cands:
        return None
    raise RuntimeError(f"ambiguous gateway discovery: {cands}")


def hsfz(src, dst, uds):
    body = bytes([src, dst]) + uds
    return struct.pack(">I", len(body)) + b"\x00\x01" + body


class ProtocolError(Exception):
    pass


class Logger:
    REQ_TIMEOUT = 1.5  # per-DID deadline, seconds (monotonic)

    def __init__(self, gw_ip):
        self.gw = gw_ip
        self.sock = None
        self.rx = b""  # connection-owned receive buffer; cleared on reconnect
        self.connect()

    def connect(self):
        self.close()
        self.sock = socket.create_connection((self.gw, 6801), timeout=8)
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        self.rx = b""  # clean stream boundary

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _send_diag(self, ecu, uds):
        # READ-ONLY ENFORCEMENT: only 3-byte UDS 0x22 reads may be sent.
        if not (len(uds) == 3 and uds[0] == 0x22):
            raise ProtocolError(f"blocked non-read UDS request: {uds.hex()}")
        self.sock.sendall(hsfz(TESTER, ecu, uds))

    def _recv_frame(self, deadline):
        """Return (msg_type, body), or (None, None) on deadline. Raises on
        EOF/protocol error. Preserves partial frames in self.rx."""
        while True:
            if len(self.rx) >= 6:
                n = struct.unpack(">I", self.rx[0:4])[0]
                mt = struct.unpack(">H", self.rx[4:6])[0]
                if n > 4096:
                    raise ProtocolError(f"oversize HSFZ frame n={n}")
                if len(self.rx) >= 6 + n:
                    body = self.rx[6:6 + n]
                    self.rx = self.rx[6 + n:]
                    return mt, body
                # else: valid but incomplete -> read more
            rem = deadline - time.monotonic()
            if rem <= 0:
                return None, None
            self.sock.settimeout(rem)
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                return None, None
            if not chunk:
                raise ConnectionError("gateway closed connection (EOF)")
            if len(self.rx) + len(chunk) > 65536:
                raise ProtocolError("rx buffer overrun")
            self.rx += chunk

    def read_did(self, ecu, did_hex):
        """Single 0x22 read. Returns dict: status ok|timeout|nrc|hsfz_0043|
        conn_fail (+ data / nrc / detail). Correlates ECU+dst+DID."""
        did = bytes.fromhex(did_hex)
        try:
            self._send_diag(ecu, bytes([0x22]) + did)
        except Exception as e:
            # Send failed: try one clean reconnect, abandon this sample.
            try:
                self.connect()
                return {"status": "reconnect", "detail": str(e)}
            except Exception as e2:
                return {"status": "conn_fail", "detail": str(e2)}
        deadline = time.monotonic() + self.REQ_TIMEOUT
        saw_pending = False
        while True:
            try:
                mt, body = self._recv_frame(deadline)
            except (ConnectionError, ProtocolError, OSError) as e:
                try:
                    self.connect()
                except Exception:
                    pass
                return {"status": "conn_fail", "detail": str(e)}
            if mt is None:
                # Unresolved timeout: reconnect for a clean stream boundary
                # so a late response can't contaminate the next DID.
                try:
                    self.connect()
                except Exception:
                    pass
                return {"status": "timeout", "pending": saw_pending}
            if mt == 0x0002:
                continue  # transport ACK/echo: ignore
            if mt == 0x0043:
                # Bad destination: routing problem. Alert, don't blind-retry.
                return {"status": "hsfz_0043", "detail": "gateway: incorrect destination"}
            if mt != 0x0001 or len(body) < 5:
                continue  # non-diagnostic or malformed: discard
            if body[0] != ecu or body[1] != TESTER:
                continue  # not addressed to us / not from requested ECU
            svc = body[2]
            if svc == 0x62 and body[3:5] == did:
                return {"status": "ok", "data": body[5:]}
            if svc == 0x7F and len(body) >= 7 and body[3] == 0x22 and body[4:6] == did:
                nrc = body[6]
                if nrc == 0x78:
                    saw_pending = True  # response pending: keep waiting
                    continue
                return {"status": "nrc", "nrc": f"{nrc:02X}"}
            # Correlated address, unexpected service/DID: discard, keep waiting.
            continue


def main():
    if len(sys.argv) > 1:
        outpath = sys.argv[1]
    else:
        outpath = time.strftime("g30_drive_log_%Y%m%d_%H%M%S.jsonl")
    duration = 0.0
    if len(sys.argv) > 2:
        try:
            duration = float(sys.argv[2])
        except ValueError:
            print(f"ERROR: bad duration {sys.argv[2]!r}", flush=True)
            sys.exit(2)
        if not math.isfinite(duration) or duration < 0:
            print("ERROR: duration must be a finite non-negative number (0 = until Ctrl+C)",
                  flush=True)
            sys.exit(2)
    # Exclusive creation: never silently truncate an existing log.
    if os.path.exists(outpath):
        print(f"ERROR: {outpath} exists; refusing to overwrite. Pick another name.",
              flush=True)
        sys.exit(2)

    print("Discovering gateway...", flush=True)
    try:
        gw = discover_gateway()
    except RuntimeError as e:
        print(f"ERROR: {e}", flush=True)
        sys.exit(1)
    if not gw:
        print("ERROR: gateway not found. Is ENET plugged in + car in diag mode?",
              flush=True)
        sys.exit(1)
    print(f"Gateway: {gw}", flush=True)
    log = Logger(gw)

    # Group channels by (ecu, did): 20 channels from 18 unique reads.
    seen = {}
    for ecu, did, name, fn in CHANNELS:
        seen.setdefault((ecu, did), []).append((name, fn))

    t_start_mono = time.monotonic()
    t_start_wall = time.time()
    n = 0
    err_counts = {}
    try:
        with open(outpath, "w") as f:
            f.write(json.dumps({"type": "meta", "gateway": gw,
                                "t_start_wall": t_start_wall,
                                "read_only": "UDS 0x22 only",
                                "channels": [c[2] for c in CHANNELS]}) + "\n")
            while True:
                elapsed = time.monotonic() - t_start_mono
                if duration and elapsed > duration:
                    break
                row = {"t": round(elapsed, 3)}
                did_ts = {}
                for (ecu, did), names in seen.items():
                    # Stop-duration check between requests (bounded overrun).
                    if duration and (time.monotonic() - t_start_mono) > duration:
                        row["_partial"] = True
                        break
                    res = log.read_did(ecu, did)
                    now = round(time.monotonic() - t_start_mono, 3)
                    key = f"{ecu:02X}:{did}"
                    if res["status"] == "ok":
                        raw = res["data"]
                        did_ts[key] = now
                        for name, fn in names:
                            need = MIN_LEN.get(name, 1)
                            if len(raw) < need:
                                row[name] = None
                                row[name + "_raw"] = raw.hex()
                                continue
                            try:
                                row[name] = fn(raw)
                            except Exception:
                                row[name] = None
                                row[name + "_raw"] = raw.hex()
                    else:
                        err_counts[res["status"]] = err_counts.get(res["status"], 0) + 1
                        for name, _ in names:
                            row[name] = None
                        # Keep first error context per sweep for diagnosis.
                        if "_err" not in row:
                            row["_err"] = {"did": key, **{k: v for k, v in res.items()
                                                          if k != "data"}}
                        if res["status"] == "hsfz_0043":
                            print(f"  !! HSFZ 0043 on {key}: gateway refusing destination",
                                  flush=True)
                # Derived: TCC slip from temporally adjacent RPM readings.
                try:
                    rpm, trb = row.get("dme_rpm"), row.get("egs_turbine")
                    if rpm is not None and trb is not None:
                        skew = abs(did_ts.get("12:4807", 0) - did_ts.get("18:DA2A", 0))
                        row["tcc_slip"] = round(rpm - trb, 1)
                        row["tcc_slip_skew_s"] = round(skew, 3)
                except Exception:
                    pass
                f.write(json.dumps(row) + "\n")
                n += 1
                if n % 20 == 0:
                    f.flush()
                    os.fsync(f.fileno())
                    print(f"  {n} sweeps, {time.monotonic()-t_start_mono:.0f}s, "
                          f"errors={err_counts}", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        log.close()
    print(f"Done: {n} sweeps -> {outpath} errors={err_counts}", flush=True)


if __name__ == "__main__":
    main()
