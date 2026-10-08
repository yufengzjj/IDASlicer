import itertools
import os
import pickle
from unittest import mock

import pytest
from hypothesis import given
from hypothesis import strategies as st

import idaslicer

intervals = st.lists(st.tuples(st.integers(0, 60), st.integers(1, 20)).map(lambda t: (t[0], t[0] + t[1])), max_size=12)


def _bytes_of(runs):
    return {a for s, e in runs for a in range(s, e)}


@given(intervals, st.booleans())
def test_merge_intervals_runs(ivs, touching):
    runs = idaslicer._merge_intervals(ivs, touching)
    assert runs == sorted(runs)
    assert _bytes_of(runs) == _bytes_of(ivs)
    starts = {s for s, _ in ivs}
    assert all(s in starts for s, _ in runs)
    for (_, e1), (s2, _) in itertools.pairwise(runs):
        assert e1 < s2 if touching else e1 <= s2


@given(intervals, st.sets(st.integers(0, 80)))
def test_merge_intervals_split_at(ivs, cuts):
    runs = idaslicer._merge_intervals(ivs, split_at=lambda a: a in cuts)
    assert _bytes_of(runs) == _bytes_of(ivs)
    for (_, e1), (s2, _) in itertools.pairwise(runs):
        assert e1 < s2 or (e1 == s2 and s2 in cuts)


def test_merge_intervals_overlap_ignores_split_at():
    assert idaslicer._merge_intervals([(0, 10), (5, 15)], split_at=lambda a: True) == [(0, 15)]
    assert idaslicer._merge_intervals([(0, 10), (10, 15)], split_at=lambda a: a == 10) == [(0, 10), (10, 15)]


@given(intervals, intervals)
def test_coverage_matches_byte_set(added, probes):
    cov = idaslicer._Coverage()
    seen = set()
    for s, e in added:
        cov.add(s, e)
        seen |= set(range(s, e))
        assert cov.starts == sorted(cov.starts)
        assert all(a < b for a, b in zip(cov.ends, cov.starts[1:], strict=False))
    for s, e in probes:
        assert cov.covers(s, e) == set(range(s, e)).issubset(seen)


def test_coverage_union_of_pieces():
    cov = idaslicer._Coverage()
    cov.add(0, 4)
    cov.add(4, 8)
    assert cov.covers(2, 6)
    assert not cov.covers(2, 9)


@given(st.integers(1, 70), st.data())
def test_read_range_runs_follow_mask(size, data):
    has_value = data.draw(st.lists(st.booleans(), min_size=size, max_size=size))
    bits = sum(1 << i for i, v in enumerate(has_value) if v)
    nbytes = (size + 7) // 8
    # Bits past `size` in the last mask byte are padding and must be ignored.
    pad = data.draw(st.integers(0, (1 << (nbytes * 8 - size)) - 1)) << size
    mask = (bits | pad).to_bytes(nbytes, "little")
    content = bytes(range(size))
    with mock.patch.object(idaslicer.ida_bytes, "get_bytes_and_mask", lambda ea, n: (content, mask)):
        got, runs = idaslicer._read_range(0x1000, size)
    assert got == (content if any(has_value) else b"")
    assert _bytes_of((o, o + n) for o, n in runs) == {i for i, v in enumerate(has_value) if v}
    assert all(n > 0 for _, n in runs)
    assert all(o1 + n1 < o2 for (o1, n1), (o2, _) in itertools.pairwise(runs))


def test_read_range_odd_mask_means_all_values(monkeypatch):
    monkeypatch.setattr(idaslicer.ida_bytes, "get_bytes_and_mask", lambda ea, n: (b"\x01" * 16, b"\x00"))
    assert idaslicer._read_range(0, 16) == (b"\x01" * 16, [(0, 16)])


def test_read_range_nothing(monkeypatch):
    monkeypatch.setattr(idaslicer.ida_bytes, "get_bytes_and_mask", lambda ea, n: None)
    assert idaslicer._read_range(0, 16) == (None, [])
    assert idaslicer._read_range(0, 0) == (None, [])


@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_seg_unpickler_loads_plain_payload(tmp_path, protocol):
    payload = {"version": 1, "content": b"\x00\xffabc", "inited": [(0, 2)], "names": [[0, "x"]], "seg_type": None, "merged": True}
    path = tmp_path / "a.seg"
    path.write_bytes(pickle.dumps(payload, protocol=protocol))
    with open(path, "rb") as f:
        assert idaslicer._SegUnpickler(f).load() == payload


class _Evil:
    def __init__(self, marker):
        self.marker = marker

    def __reduce__(self):
        return (os.mkdir, (self.marker,))


def test_seg_unpickler_refuses_code(tmp_path):
    marker = str(tmp_path / "pwned")
    path = tmp_path / "evil.seg"
    path.write_bytes(pickle.dumps({"content": _Evil(marker)}))
    with open(path, "rb") as f, pytest.raises(pickle.UnpicklingError):
        idaslicer._SegUnpickler(f).load()
    assert not os.path.exists(marker)


@given(st.text(max_size=300), st.text(alphabet="_0x123456789abcdef.seg", max_size=40), st.integers(1, 300))
def test_truncate_filename_name(name, suffix, limit):
    out = idaslicer._truncate_filename_name(name, suffix, limit)
    assert name.startswith(out)
    if len(suffix.encode()) >= limit:
        assert out == ""
    else:
        assert len((out + suffix).encode()) <= limit
        if len((name + suffix).encode()) <= limit:
            assert out == name


@pytest.mark.parametrize(
    "stored, expected",
    [
        (
            {"max_explore_len": 64, "skip_named_data": True, "autosave_minutes": 0, "autosave_keep": 3},
            {"max_explore_len": 64, "skip_named_data": True, "autosave_minutes": 0, "autosave_keep": 3},
        ),
        ({"autosave_minutes": -1, "autosave_keep": 0}, idaslicer.DEFAULT_SETTINGS),
        ({"autosave_minutes": False, "autosave_keep": "5"}, idaslicer.DEFAULT_SETTINGS),
        ({"max_explore_len": True, "skip_named_data": 1}, idaslicer.DEFAULT_SETTINGS),
        ({"max_explore_len": -1}, idaslicer.DEFAULT_SETTINGS),
        ({"max_explore_len": "64"}, idaslicer.DEFAULT_SETTINGS),
        (["max_explore_len"], idaslicer.DEFAULT_SETTINGS),
        (None, idaslicer.DEFAULT_SETTINGS),
    ],
)
def test_apply_stored_settings(monkeypatch, stored, expected):
    monkeypatch.setattr(idaslicer, "SETTINGS", dict(idaslicer.DEFAULT_SETTINGS))
    idaslicer._apply_stored_settings(stored)
    assert idaslicer.SETTINGS == expected


def test_added_msg():
    assert idaslicer._added_msg(2, 0) == "Added 2 ranges to the slicer list."
    assert idaslicer._added_msg(0, 3) == "Extended 3 existing ranges."
    assert idaslicer._added_msg(1, 1) == "Added 1 ranges and extended 1 existing ones."
    assert idaslicer._added_msg(0, 0) == "Added 0 ranges to the slicer list."


@pytest.mark.parametrize(
    "text, expected",
    [
        ("0x1000", 0x1000),
        (" 0XaBc ", 0xABC),
        ("0x1000-0x2000", None),
        ("1000", None),
        ("sub_1000", None),
        ("", None),
    ],
)
def test_parse_addr_query(text, expected):
    assert idaslicer._parse_addr_query(text) == expected


def test_worker_markers_match_host():
    assert f'"{idaslicer.WORKER_PROBLEM}' in idaslicer.WORKER_SCRIPT
    assert f"sys.exit({idaslicer.WORKER_EXIT_PROBLEMS})" in idaslicer.WORKER_SCRIPT
