"""Synthetic fake-car fixtures; 0x1234 is NOT a discovered BMW DID."""
import io
import json
import queue
import threading
from types import MethodType, SimpleNamespace
from unittest.mock import Mock

import pytest

from src.bmw_enet_tool import sensors
from src.bmw_enet_tool.dashboard_app import Dashboard
from src.bmw_enet_tool.protocol import TESTER, hsfz, parse_hsfz


class FakeSocket:
    def __init__(self):
        self.sent = []

    def sendall(self, frame):
        self.sent.append(frame)


@pytest.fixture
def poller(registry):
    synthetic = dict(sensors._BUILTIN_DEFAULTS[0], sensor_id="synthetic", ecu=0x18,
                     did=0x1234, scale=1.0, size=2)
    sensors.add_sensor(synthetic)
    app = SimpleNamespace(
        _sock=FakeSocket(), _send_lock=threading.Lock(), _rx_buf=b"", _pkt_queue=queue.Queue(),
        _poll_pending=None, _poll_gen=0, _poll_idx=0, _poll_ecu=None, _poll_stage=None,
        _poll_mode="dynamic", _polling=True, _running=True, _disabled_gauges=set(),
        _poll_timeout_id=None, _poll_delay=20, _gauges={"synthetic": Mock()},
        _poll_queue=[(0x18, 0x1234, 2, float, "synthetic")],
        after=Mock(return_value="timer"), after_cancel=Mock(), _evt=Mock(),
        _last_sensor_time=None, _delay_samples=[], _delay_var=Mock(), _poll_status=Mock(),
        _samples={}, _raw_latest={}, _log_latest={}, _logging=True, _log_file=io.StringIO(),
        _log_row_count=0, _replay_state="idle")
    for name in ("_do_send", "_parse_rx", "_poll_next", "_complete_poll", "_drain_queue",
                 "_poll_stall_timeout", "_log_write", "_update_derived"):
        setattr(app, name, MethodType(getattr(Dashboard, name), app))
    return app


def receive(app, uds, src=0x18, msg_type=1):
    frame = hsfz(src, TESTER, uds)
    app._rx_buf += frame[:4] + msg_type.to_bytes(2, "big") + frame[6:]
    app._parse_rx()


def test_hsfz_roundtrip_and_truncated():
    uds = bytes.fromhex("22 F3 00")
    frame = hsfz(TESTER, 0x18, uds)
    assert frame == bytes.fromhex("00 00 00 05 00 01 F4 18 22 F3 00")
    assert parse_hsfz(frame) == (TESTER, 0x18, uds, len(frame), 1)
    for length in range(len(frame)):
        assert parse_hsfz(frame[:length]) is None


def test_dynamic_sequence_byte_exact(poller):
    app = poller
    app._poll_next()
    receive(app, bytes.fromhex("6C 01 F3 00"))
    receive(app, bytes.fromhex("62 F3 00 0B B8"))
    app._drain_queue()
    assert app._sock.sent == [bytes.fromhex(s) for s in (
        "00 00 00 0A 00 01 F4 18 2C 01 F3 00 12 34 01 02",
        "00 00 00 05 00 01 F4 18 22 F3 00",
        "00 00 00 06 00 01 F4 18 2C 03 F3 00",
    )]
    app._gauges["synthetic"].update_value.assert_called_once_with(3000., 3000)
    row = json.loads(app._log_file.getvalue())
    assert row["d"]["synthetic"] == 3000
    assert row["raw"]["synthetic"] == 3000
    assert len(row["ts"].rsplit(".", 1)[1]) == 3
    receive(app, bytes.fromhex("6C 03 F3 00"))
    assert app._pkt_queue.get_nowait() == ("poll_next", 1)


def test_echo_wrong_ecu_and_short_payload_ignored(poller):
    poller._poll_next()
    receive(poller, bytes.fromhex("6C 01 F3 00"), msg_type=2)
    receive(poller, bytes.fromhex("6C 01 F3 00"), src=0x12)
    assert len(poller._sock.sent) == 1
    receive(poller, bytes.fromhex("6C 01 F3 00"))
    receive(poller, bytes.fromhex("62 F3 00 01"))
    assert poller._pkt_queue.empty()
    assert poller._poll_pending is not None


def test_nrc_routed(poller):
    uds = bytes.fromhex("7F 2C 31")
    receive(poller, uds)
    assert poller._pkt_queue.get_nowait() == ("nrc", uds)


def test_direct_mode(poller):
    sensors.update_sensor("synthetic", {"read_mode": "direct"})
    poller._poll_next()
    receive(poller, bytes.fromhex("62 12 34 00 32"))
    poller._drain_queue()
    assert poller._sock.sent == [bytes.fromhex("00 00 00 05 00 01 F4 18 22 12 34")]
    poller._gauges["synthetic"].update_value.assert_called_once_with(50., 50)
    # Unsolicited direct data after completion must not crash or update gauges.
    receive(poller, bytes.fromhex("62 12 34 00 33"))
    assert poller._pkt_queue.empty()


@pytest.mark.parametrize("nrc", [0x31, 0x12])
def test_poll_direct_fallback(poller, nrc):
    poller._poll_next()
    receive(poller, bytes([0x7F, 0x2C, nrc]))
    poller._drain_queue()
    assert poller._sock.sent[-1] == hsfz(TESTER, 0x18, bytes.fromhex("22 12 34"))
    receive(poller, bytes.fromhex("62 12 34 00 32"))
    poller._drain_queue()
    assert len(poller._sock.sent) == 2  # direct response must not trigger clear


def test_late_data_after_stop_not_logged(poller):
    poller._poll_next()
    receive(poller, bytes.fromhex("6C 01 F3 00"))
    receive(poller, bytes.fromhex("62 F3 00 00 32"))
    poller._polling = False
    poller._drain_queue()
    assert poller._log_file.getvalue() == ""
