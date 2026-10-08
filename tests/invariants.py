import ida_segment

import idaslicer


def coverage(ranges):
    cov = idaslicer._Coverage()
    for s, e in ranges:
        cov.add(s, e)
    return cov


def check_scan(db, seed, ranges, origins):
    """What every scan result must satisfy, whatever it collected."""
    assert ranges
    seen = idaslicer._Coverage()
    for s, e in ranges:
        assert s < e
        seg = ida_segment.getseg(s)
        assert seg is not None and e <= seg.end_ea, f"{db.label(s)}-{db.label(e)} leaves its segment"
        # What makes the scan terminate: each range adds a byte not seen before.
        assert not seen.covers(s, e), f"{db.label(s)}-{db.label(e)} was already covered"
        seen.add(s, e)
    assert seed not in origins
    for referrer in origins.values():
        assert seen.covers(referrer, referrer + 1), f"referrer {db.label(referrer)} is outside the scan"


def check_own_in_recursive(db, seed):
    rec = coverage(idaslicer.collect_recursive_ranges(seed))
    for s, e in idaslicer.collect_function_ranges(seed):
        assert rec.covers(s, e), f"{db.label(s)}-{db.label(e)}"
