import copy
import json

import pytest

from src.bmw_enet_tool import profiles, sensors
from src.bmw_enet_tool.polling import build_poll_queue


def test_f10_defaults_frozen():
    # Frozen upstream specifications, including all original scales/calibrations.
    columns = ("sensor_id", "label", "did", "ecu", "size", "unit", "min", "max",
               "warn", "danger", "decimals", "scale", "offset", "calibration_raw", "calibration_value")
    rows = [
        ("engine_rpm", "Engine RPM", 0x4807, 0x12, 2, "RPM", 0, 8000, 5500, 7000, 0, .25, 0., 3374, 843.5),
        ("battery_voltage", "Battery Voltage", 0x5815, 0x12, 1, "V", 9, 16, 14.8, 11., 2, .1, 0., 147, 14.7),
        ("lp_fuel_pressure", "LP Fuel Pressure", 0x58F3, 0x12, 2, "PSI", 0, 145, 116, 130, 1, .0145038, 0., 6015, 87.23),
        ("hp_rail_pressure", "HP Rail Pressure", 0x58F0, 0x12, 2, "PSI", 0, 2900, 2610, 2830, 1, .0725, 0., 10230, 741.68),
        ("coolant_temp", "Coolant Temp", 0x4300, 0x12, 1, "°C", 0, 130, 100, 115, 1, .5, -3.5, 207, 100.),
        ("oil_pressure", "Oil Pressure", 0x586F, 0x12, 2, "PSI", 0, 90, 75, 85, 1, .0145675, 0., 2732, 39.80),
        ("engine_oil_temp", "Engine Oil Temp", 0x4402, 0x12, 2, "°C", 0, 150, 120, 135, 1, .51275510, 0., 196, 100.50),
        ("boost_pressure", "Boost Pressure", 0x58DD, 0x12, 2, "PSI", 0, 30, 25, 28, 2, .00113310, 0., 12985, 14.71),
        ("throttle_angle", "Throttle Angle", 0x4600, 0x12, 2, "%", 0, 100, 90, 95, 1, .02437500, 0., 112, 2.73),
        ("intake_pressure", "Intake Pressure", 0x580B, 0x12, 2, "PSI", 0, 15, 13, 14, 2, .00056536, 0., 24752, 13.99),
        ("valvetronic_angle", "Valvetronic Angle", 0x58A2, 0x12, 2, "deg", 0, 60, 50, 55, 1, .1, 0., 253, 25.30),
    ]
    frozen = [dict(zip(columns, row)) for row in rows]
    assert profiles.F10_N55 == sensors._BUILTIN_DEFAULTS == frozen


def test_g30_honesty():
    for old, new in zip(profiles.F10_N55, profiles.G30_B58):
        assert all(new[key] == value for key, value in old.items())
        assert new["verified"] is False
        assert new["confidence"] == "candidate"
        assert new["source"] == "carried from F10/N55, unverified on B58"
    expected = {"turbine_speed", "output_speed", "tcc_slip", "lockup_status", "actual_gear",
                "target_gear", "fluid_temp", "input_torque", "gear_ratio", "shift_status",
                "line_pressure", "clutch_pressures", "solenoid_currents", "adaptation_values",
                "voltage", "fault_flags"}
    egs = [s for s in profiles.G30_B58 if s["sensor_id"].startswith("egs_")]
    assert {s["sensor_id"][4:] for s in egs} == expected
    for s in egs:
        assert s["did"] is None
        assert s["confidence"] == "unknown"
        assert s["source"] == "placeholder for DID scanner discovery"
        assert s["ecu"] == 0x18
        assert s["ecu_confidence"] == "researched"
        assert "candidate" in s["ecu_source"] and "unverified" in s["ecu_source"]
        assert (s["scale"], s["offset"]) == (1.0, 0.0)
    assert all(s["verified"] is False for s in profiles.G30_B58)
    assert all(sensors._validate_sensor(s)[0] for s in profiles.G30_B58)


def test_profile_backup_and_persistence(registry):
    sensors.update_sensor("engine_rpm", {"label": "Owner custom RPM"})
    original = registry.read_bytes()
    backup = profiles.switch_profile("G30_B58", registry)
    from pathlib import Path
    assert Path(backup).read_bytes() == original
    assert Path(backup).name.startswith("sensor.json.bak-")
    assert sensors.load_sensors(registry) == (True, "")
    assert sensors.get_sensors() == profiles.G30_B58
    assert sensors.get_vehicle_profile() == "G30_B58"
    assert json.loads(registry.read_text())["profile"] == "G30_B58"
    template = profiles.get_profile("G30_B58")
    template[0]["label"] = "Changed"
    assert profiles.G30_B58[0]["label"] == "Engine RPM"


@pytest.mark.parametrize("field,value", [
    ("verified", "false"), ("source", 1), ("vehicle", None), ("confidence", "certain"),
    ("read_mode", "write"), ("did", 0x10000), ("ecu", 0x100), ("size", 256),
    ("derived_fn", "eval"), ("derived_from", ["only_one"]),
])
def test_invalid_metadata(field, value):
    s = dict(profiles.G30_B58[0], **{field: value})
    assert not sensors._validate_sensor(s)[0]


def test_metadata_preserved_on_edit(registry):
    profiles.switch_profile("G30_B58", registry)
    sid = "egs_turbine_speed"
    before = copy.deepcopy(sensors.get_sensor_by_id(sid))
    assert sensors.update_sensor(sid, {"read_mode": "direct"}) == (True, "")
    assert sensors.load_sensors(registry) == (True, "")
    assert sensors.get_sensor_by_id(sid) == dict(before, read_mode="direct")


def test_unknown_and_derived_skip_polling(caplog):
    result = build_poll_queue(profiles.G30_B58)
    assert len(result) == len(profiles.F10_N55)
    assert all(e[1] is not None for e in result)
    assert "Skipping egs_turbine_speed" in caplog.text
    # A derived-only layout polls its source, not the calculated channel.
    result = build_poll_queue(profiles.G30_B58, ["tcc_slip_calc"])
    assert [e[4] for e in result] == ["engine_rpm"]
