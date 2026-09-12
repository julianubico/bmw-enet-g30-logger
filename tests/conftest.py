import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.bmw_enet_tool import sensors


@pytest.fixture
def registry(tmp_path, monkeypatch):
    """CRUD tests must never overwrite the owner's sensor registry."""
    path = tmp_path / "sensor.json"
    with monkeypatch.context() as patch:
        patch.setattr(sensors, "_sensor_list", [])
        patch.setattr(sensors, "_sensor_map", {})
        patch.setattr(sensors, "_vehicle_profile", "F10_N55")
        patch.setattr(sensors, "_resolve_sensor_json_path", lambda: str(path))
        sensors.replace_sensors(sensors._BUILTIN_DEFAULTS, "F10_N55")
        yield path
    sensors._rebuild_compat()
