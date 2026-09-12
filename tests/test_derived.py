import pytest

from src.bmw_enet_tool.derived import compute_derived, slip_rpm
from src.bmw_enet_tool.profiles import G30_B58

SLIP = next(s for s in G30_B58 if s["sensor_id"] == "tcc_slip_calc")


def test_slip_math():
    assert slip_rpm(3000, 2950) == 50
    assert slip_rpm(2950, 3000) == -50
    samples = {"engine_rpm": (3000, 10), "egs_turbine_speed": (2950, 10.1)}
    assert compute_derived(SLIP, samples, 11.999) == 50


@pytest.mark.parametrize("samples,now", [
    ({}, 10),
    ({"engine_rpm": (3000, 10)}, 10),
    ({"engine_rpm": (3000, 10), "egs_turbine_speed": (2950, 11)}, 12),
    ({"engine_rpm": (3000, 11), "egs_turbine_speed": (2950, 10)}, 12),
    ({"engine_rpm": (3000, 10), "egs_turbine_speed": (2950, 11)}, 9),
])
def test_stale_missing_future_sources(samples, now):
    assert compute_derived(SLIP, samples, now) is None
