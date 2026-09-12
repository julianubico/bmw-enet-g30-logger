"""Vehicle sensor profiles.

F10_N55 is the upstream default set (2011-2016 535i, N55) — byte-for-value
identical to the upstream built-in defaults in sensors.py.

G30_B58 is the experimental G30 540i (B58 + ZF 8HP) profile.  Its DME
entries are carried over from the F10/N55 map UNVERIFIED: every DME sensor
is marked verified=False / confidence="candidate" and must be re-checked on
the real car before any value is trusted.  The EGS (transmission) entries
are placeholders with did=None: no public G30/B58 or ZF8 DID map was found,
so their DIDs have to be discovered on Julian's 2018 540i with the DID
scanner (did_scanner.py) or from an ISTA-over-ENET Wireshark capture.
Nothing here is hard-coded guesswork.

Read-only policy: the scanner and logger only ever use UDS 0x22 (read data)
and 0x2C (define/clear dynamic DID).  No writes, no routines, no resets.
"""

import copy
from datetime import datetime

from .sensors import _BUILTIN_DEFAULTS

#: F10 535i (N55) — the upstream default set, preserved exactly.
F10_N55 = [dict(s) for s in _BUILTIN_DEFAULTS]


def _carried_dme():
    """Copy the F10 DME map, flagged as unverified on the B58."""
    out = []
    for s in F10_N55:
        c = dict(s)
        c["verified"] = False
        c["confidence"] = "candidate"
        c["source"] = "carried from F10/N55, unverified on B58"
        out.append(c)
    return out


#: Candidate EGS (transmission control) address.  Researched from public BMW
#: UDS/ECU-address references, NOT verified on Julian's car — the scanner
#: validates per-DID responses against the pending ECU before accepting them.
EGS_ECU_CANDIDATE = 0x18

_EGS_PLACEHOLDERS = [
    # (sensor_id, label, unit, min, max, decimals)
    ("egs_turbine_speed",   "Turbine Speed",       "RPM",   0,    8000,  0),
    ("egs_output_speed",    "Output Speed",        "RPM",   0,    8000,  0),
    ("egs_tcc_slip",        "TCC Slip",            "RPM",  -2000, 2000,  0),
    ("egs_lockup_status",   "Lockup Clutch State", "",      0,    3,     0),
    ("egs_actual_gear",     "Actual Gear",         "",      0,    8,     0),
    ("egs_target_gear",     "Target Gear",         "",      0,    8,     0),
    ("egs_fluid_temp",      "Trans Fluid Temp",    "°C",   -40,   150,   1),
    ("egs_input_torque",    "Input Torque",        "Nm",    0,    800,   0),
    ("egs_gear_ratio",      "Gear Ratio",          ":1",    0,    8,     3),
    ("egs_shift_status",    "Shift State",         "",      0,    8,     0),
    ("egs_line_pressure",   "Line Pressure",       "bar",   0,    25,    1),
    ("egs_clutch_pressures","Clutch Pressures",    "bar",   0,    25,    1),
    ("egs_solenoid_currents","Solenoid Currents",   "A",     0,    2,     2),
    ("egs_adaptation_values","Adaptation Values",   "",     -500, 500,   0),
    ("egs_voltage",         "EGS Voltage",         "V",     9,    16,    2),
    ("egs_fault_flags",     "Fault Flags",         "",      0,    255,   0),
]


def _egs_placeholder(sensor_id, label, unit, vmin, vmax, decimals):
    return {
        "sensor_id": sensor_id,
        "label": label,
        "did": None,                      # undiscovered — scanner fills this in
        "ecu": EGS_ECU_CANDIDATE,
        "size": 2,
        "unit": unit,
        "min": vmin,
        "max": vmax,
        "decimals": decimals,
        "scale": 1.0,
        "offset": 0.0,
        "verified": False,
        "confidence": "unknown",
        "source": "placeholder for DID scanner discovery",
        "ecu_confidence": "researched",
        "ecu_source": "candidate EGS address, unverified on this vehicle",
        "read_mode": "dynamic",
    }


_TCC_SLIP_CALC = {
    "sensor_id": "tcc_slip_calc",
    "label": "TCC Slip (calc)",
    "did": None,                          # derived — never polled directly
    "ecu": EGS_ECU_CANDIDATE,
    "size": 2,
    "unit": "RPM",
    "min": -2000,
    "max": 2000,
    "decimals": 0,
    "scale": 1.0,
    "offset": 0.0,
    "verified": False,
    "confidence": "candidate",
    "source": "derived: engine_rpm − egs_turbine_speed",
    "ecu_confidence": "researched",
    "ecu_source": "candidate EGS address, unverified on this vehicle",
    "read_mode": "dynamic",
    "derived_fn": "slip_rpm",
    "derived_from": ["engine_rpm", "egs_turbine_speed"],
}

G30_B58 = (
    _carried_dme()
    + [_egs_placeholder(*row) for row in _EGS_PLACEHOLDERS]
    + [dict(_TCC_SLIP_CALC)]
)

PROFILES = {
    "F10_N55": F10_N55,
    "G30_B58": G30_B58,
}

DEFAULT_PROFILE = "F10_N55"


def get_profile(name):
    """Return a deep copy of the named vehicle profile template.

    Raises ValueError for unknown names.  The returned list is a private
    copy — mutating it never affects the built-in templates.
    """
    try:
        template = PROFILES[name]
    except KeyError:
        raise ValueError(
            f"Unknown vehicle profile: {name!r} "
            f"(known: {', '.join(sorted(PROFILES))})"
        )
    return copy.deepcopy(template)


def switch_profile(name, path):
    """Replace the live sensor registry with the named profile template.

    Backs up the current sensor.json first.  Returns the backup path.
    Scanner discoveries land in the *live* registry, never in the
    built-in templates, so they survive profile switches only via export.
    """
    from pathlib import Path
    from . import sensors

    template = get_profile(name)  # validates the name
    p = Path(path)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = Path(f"{p}.bak-{stamp}")
    backup.write_bytes(p.read_bytes() if p.exists() else b"")
    sensors.replace_sensors(template, name, path=str(p))
    return str(backup)
