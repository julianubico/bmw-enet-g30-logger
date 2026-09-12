"""Poll-queue construction for the live dashboard.

The dashboard polls sensors round-robin with UDS 0x2C (define dynamic DID)
or, where the ECU does not support 0x2C, plain 0x22 reads.  This module
decides *which* sensors enter the queue:

* sensors with did=None (undiscovered placeholders) are skipped,
* derived-only channels are skipped — their *source* sensors are queued
  instead (so asking for tcc_slip_calc alone still polls engine_rpm).
"""

import logging

from .sensors import _make_scale_fn

log = logging.getLogger(__name__)


def build_poll_queue(sensor_list, only_ids=None):
    """Build [(ecu, did, size, scale_fn, sensor_id), ...] for live polling.

    sensor_list: registry dicts (as from sensors.get_sensors()).
    only_ids: optional subset of sensor_ids to poll.  Derived ids in this
    list are expanded to their source sensors; unknown ids are ignored.
    """
    by_id = {s["sensor_id"]: s for s in sensor_list}

    wanted = []
    if only_ids is None:
        wanted = [s["sensor_id"] for s in sensor_list]
    else:
        for sid in only_ids:
            s = by_id.get(sid)
            if s is None:
                continue
            if s.get("derived_from"):
                wanted.extend(s["derived_from"])
            else:
                wanted.append(sid)

    queue = []
    seen = set()
    for sid in wanted:
        if sid in seen:
            continue
        seen.add(sid)
        s = by_id.get(sid)
        if s is None:
            continue
        if s.get("derived_from"):
            continue  # derived channel — sources already queued above
        if s.get("did") is None:
            log.warning(
                "Skipping %s: no DID mapped yet (run the DID scanner)", sid
            )
            continue
        queue.append((
            s["ecu"],
            s["did"],
            s["size"],
            _make_scale_fn(s.get("scale", 1.0), s.get("offset", 0.0)),
            sid,
        ))
    return queue
