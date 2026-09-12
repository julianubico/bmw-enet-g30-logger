"""Synthetic diagnostic replies, not BMW DID mappings."""
import json
import socket
import threading

import pytest

from src.bmw_enet_tool import profiles, sensors
from src.bmw_enet_tool.did_scanner import (
    DIDScanner, ScannerTransport, apply_discovery, export_report, guard_service,
    parse_candidates,
)
from src.bmw_enet_tool.protocol import TESTER, hsfz, parse_hsfz


@pytest.mark.parametrize("service", [0x2E, 0x31, 0x34, 0x36, 0x37, 0x11, 0x27, 0x28, 0x85])
def test_guard_refuses(service):
    with pytest.raises(ValueError):
        guard_service(bytes([service]))


@pytest.mark.parametrize("service", [0x22, 0x2C])
def test_guard_accepts(service):
    guard_service(bytes([service]))


def test_empty_guard():
    with pytest.raises(ValueError):
        guard_service(b"")


class SyntheticCar:
    def __init__(self, define_nrc=None, read_nrc=None, stop=None):
        self.sent = []
        self.rx = b""
        self.size = 2
        self.define_nrc = define_nrc
        self.read_nrc = read_nrc
        self.stop = stop

    def settimeout(self, timeout):
        pass

    def sendall(self, frame):
        self.sent.append(frame)
        src, ecu, uds, _, _ = parse_hsfz(frame)
        assert src == TESTER and ecu == 0x18
        assert uds[0] in (0x22, 0x2C)
        if uds[:2] == b"\x2c\x01":
            self.size = uds[-1]
            response = bytes([0x7F, 0x2C, self.define_nrc]) if self.define_nrc else b"\x6c\x01\xf3\x00"
        elif uds[:2] == b"\x2c\x03":
            response = b"\x6c\x03\xf3\x00"
        else:
            if self.read_nrc:
                response = bytes([0x7F, 0x22, self.read_nrc])
            else:
                # Direct reads return their actual width, independent of probe size.
                width = 2 if self.define_nrc else self.size
                response = b"\x62" + uds[1:] + (50).to_bytes(width, "big")
            if self.stop:
                self.stop.set()
        # Echo and unrelated ECU frames precede every real response.
        echo = frame[:4] + b"\x00\x02" + frame[6:]
        self.rx += echo + hsfz(0x12, TESTER, response) + hsfz(ecu, TESTER, response)

    def recv(self, size):
        if not self.rx:
            raise socket.timeout()
        # Exercise fragmentation and concatenated frame parsing together.
        chunk, self.rx = self.rx[:7], self.rx[7:]
        return chunk


def scan(car):
    transport = ScannerTransport(car, timeout=.03)
    return DIDScanner(transport, sample_interval=0).scan(0x18, [0x1234])


def test_dynamic_scan_and_report(tmp_path):
    car = SyntheticCar()
    report = scan(car)
    assert len(report["results"]) == 3
    assert report["verified"] is False
    assert report["ecu"] == 0x18 and report["timestamp"]
    for result, size in zip(report["results"], (1, 2, 4)):
        assert result["status"] == "positive"
        assert result["size"] == result["payload_length"] == size
        assert len(result["samples"]) == 5
        assert result["raw_min"] == result["raw_max"] == 50
        assert result["clear"]["status"] == "positive"
        assert result["nrc"] is None and result["timing_ms"] >= 0
        assert "meaning/scale unknown" in result["hint"]
    assert "rpm-like" in report["results"][1]["hint"]
    requests = [parse_hsfz(f)[2] for f in car.sent]
    assert requests == sum(([
        bytes([0x2C, 1, 0xF3, 0, 0x12, 0x34, 1, size]),
        *([bytes.fromhex("22 F3 00")] * 5), bytes.fromhex("2C 03 F3 00")
    ] for size in (1, 2, 4)), [])
    path = tmp_path / "report.json"
    export_report(report, path)
    assert json.loads(path.read_text()) == report


@pytest.mark.parametrize("nrc", [0x31, 0x12])
def test_direct_fallback_and_apply(nrc, registry):
    car = SyntheticCar(define_nrc=nrc)
    report = scan(car)
    for result in report["results"]:
        assert result["read_mode"] == "direct"
        assert result["define"]["nrc"] == nrc
        assert result["payload_length"] == 2
    assert sum(parse_hsfz(f)[2] == bytes.fromhex("22 12 34") for f in car.sent) == 15
    profiles.switch_profile("G30_B58", registry)
    apply_discovery("egs_turbine_speed", 0x18, report["results"][0], report["timestamp"])
    sensors.load_sensors(registry)
    s = sensors.get_sensor_by_id("egs_turbine_speed")
    assert (s["did"], s["size"], s["read_mode"]) == (0x1234, 2, "direct")
    assert (s["scale"], s["offset"], s["verified"]) == (1.0, 0.0, False)
    assert s["confidence"] == "candidate"
    assert s["source"] == "discovered by scanner " + report["timestamp"]
    assert profiles.G30_B58[11]["did"] is None


def test_other_nrc_no_fallback():
    car = SyntheticCar(define_nrc=0x22)
    report = scan(car)
    assert all(r["status"] == "nrc" and r["nrc"] == 0x22 for r in report["results"])
    assert all(parse_hsfz(f)[2][0] == 0x2C for f in car.sent)


def test_repeat_nrc_preserved():
    report = scan(SyntheticCar(read_nrc=0x22))
    assert all(len(r["samples"]) == 5 for r in report["results"])
    assert all(s["status"] == "nrc" and s["nrc"] == 0x22
               for r in report["results"] for s in r["samples"])


def test_pending_nrc_times_out():
    report = scan(SyntheticCar(read_nrc=0x78))
    assert all(s["status"] == "timeout" and s["nrc"] == 0x78
               for r in report["results"] for s in r["samples"])


def test_stop_cleans_up_and_returns_partial():
    stop = threading.Event()
    car = SyntheticCar(stop=stop)
    transport = ScannerTransport(car, stop, timeout=.03)
    report = DIDScanner(transport, sample_interval=0).scan(0x18, [0x1234])
    assert report["stopped"]
    assert len(report["results"]) == 1
    assert report["results"][0]["cancelled"]
    assert parse_hsfz(car.sent[-1])[2] == bytes.fromhex("2C 03 F3 00")
    assert report["results"][0]["clear"]["status"] == "positive"


def test_candidate_input():
    assert parse_candidates("1234, 0x1235;1234", "1235", "1236") == [0x1234, 0x1235, 0x1236]
    for args in [("",), ("10000",), ("-1",), ("", "FFFF", "0000"), ("", "1", "")]:
        with pytest.raises(ValueError):
            parse_candidates(*args)


def test_transport_guard_on_actual_send():
    car = SyntheticCar()
    transport = ScannerTransport(car)
    with pytest.raises(ValueError):
        transport.request(0x18, b"\x2e\x12\x34", b"\x6e")
    assert car.sent == []
