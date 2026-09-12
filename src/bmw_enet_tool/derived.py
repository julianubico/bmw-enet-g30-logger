"""Derived channels: values computed from live polled sensors.

A derived sensor declares ``derived_fn`` (a key into DERIVED_FUNCTIONS) and
``derived_from`` (a list of >= 2 source sensor_ids).  The dashboard keeps
fresh (sensor_id -> (value, timestamp)) samples and re-evaluates every
derived channel whose sources just updated.

Freshness gating: a source sample older than MAX_AGE_S is stale and the
derived value is rejected (returns None).  Samples dated in the future are
rejected as well — clocks and replay data must not fabricate values.
"""

import math

#: Maximum age, in seconds, of a source sample for derived computation.
MAX_AGE_S = 2.0


def slip_rpm(engine, turbine):
    """Torque-converter slip in RPM: engine speed minus turbine speed."""
    return engine - turbine


DERIVED_FUNCTIONS = {
    "slip_rpm": slip_rpm,
}


def compute_derived(sensor, samples, now):
    """Compute one derived sensor from fresh samples.

    sensor: registry dict with ``derived_fn`` and ``derived_from``.
    samples: {sensor_id: (value, timestamp)}.
    now: current timestamp, same clock as the samples.

    Returns the derived value, or None when it cannot be computed
    (unknown function, missing source, stale or future-dated sample,
    non-finite inputs).
    """
    fn_name = sensor.get("derived_fn")
    fn = DERIVED_FUNCTIONS.get(fn_name)
    sources = sensor.get("derived_from")
    if fn is None or not isinstance(sources, list) or len(sources) < 2:
        return None

    values = []
    for sid in sources:
        sample = samples.get(sid)
        if sample is None:
            return None
        try:
            value, ts = sample
        except (TypeError, ValueError):
            return None
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return None
        if not isinstance(ts, (int, float)) or isinstance(ts, bool):
            return None
        age = now - ts
        if age < 0 or age >= MAX_AGE_S:
            return None
        values.append(value)

    try:
        result = fn(*values)
    except Exception:
        return None
    if not isinstance(result, (int, float)) or isinstance(result, bool):
        return None
    if not math.isfinite(result):
        return None
    return result
