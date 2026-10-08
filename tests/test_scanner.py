import itertools
import json
import os
import types

import ida_bytes
import ida_fixup
import ida_funcs
import ida_offset
import ida_segment
import ida_ua
import ida_xref
import idautils
import pytest
from invariants import check_own_in_recursive, check_scan, coverage

import idaslicer

FUNCS = [
    "leaf",
    "callee_a",
    "via_ptr",
    "via_ptr2",
    "dispatch",
    "walk",
    "tail_target",
    "tailer",
    "tail_target2",
    "cond_tail",
    "fill_bss",
    "uncalled",
    "root",
    "_start",
    "split_leaf",
    "split_entry",
]
DATA = ["g_counter", "g_unused", "g_table", "g_n1", "g_n2", "g_bss", "g_split", "g_msg"]
SYMBOLS = FUNCS + DATA
GOLDEN = os.path.join(os.path.dirname(__file__), "golden", "scan_arm64.json")


def test_recursive_from_root(db):
    got = db.covered(idaslicer.collect_recursive_ranges(db.ea("root")), SYMBOLS)
    assert got == set(SYMBOLS) - {"uncalled", "_start", "g_unused", "split_leaf", "split_entry", "g_split"}


@pytest.mark.parametrize(
    "func, expected",
    [
        ("root", {"root", "g_msg"}),
        # Function pointers are data here: the table comes in, the functions do not.
        ("dispatch", {"dispatch", "g_table"}),
        # Data-to-data pointers are still followed.
        ("walk", {"walk", "g_n1", "g_n2"}),
        # A tail call is a call.
        ("tailer", {"tailer"}),
        ("cond_tail", {"cond_tail"}),
        ("fill_bss", {"fill_bss", "g_bss"}),
        ("split_leaf", {"split_leaf", "g_split"}),
        ("leaf", {"leaf", "g_counter"}),
    ],
)
def test_function_only(db, func, expected):
    assert db.covered(idaslicer.collect_function_ranges(db.ea(func)), SYMBOLS) == expected


def test_origins(db):
    origins = {}
    idaslicer.collect_recursive_ranges(db.ea("root"), origins)
    assert db.ea("root") not in origins
    ref = {db.label(k): db.label(v) for k, v in origins.items()}
    assert ref["callee_a"].startswith("root+")
    # fill_bss calls leaf too, but later: the first discovery wins.
    assert ref["leaf"].startswith("callee_a+")
    assert ref["tail_target"].startswith("tailer+")
    assert ref["tail_target2"].startswith("cond_tail+")
    assert ref["g_table"].startswith("dispatch+")
    assert ref["g_n2"] == "g_n1"


@pytest.mark.parametrize("func", FUNCS)
@pytest.mark.parametrize("recursive", [True, False], ids=["recursive", "own"])
def test_scan_invariants(db, func, recursive):
    origins = {}
    collect = idaslicer.collect_recursive_ranges if recursive else idaslicer.collect_function_ranges
    check_scan(db, db.ea(func), collect(db.ea(func), origins), origins)


@pytest.mark.parametrize("func", FUNCS)
def test_own_scan_is_part_of_recursive(db, func):
    check_own_in_recursive(db, db.ea(func))


def test_golden(db, request):
    """Everything each function's scans collect, as symbol labels. On a
    deliberate change, rerun with --update-golden and review the diff."""
    got = {
        f: {
            "own": db.labels(idaslicer.collect_function_ranges(db.ea(f))),
            "recursive": db.labels(idaslicer.collect_recursive_ranges(db.ea(f))),
        }
        for f in FUNCS
    }
    if request.config.getoption("--update-golden") or not os.path.exists(GOLDEN):
        os.makedirs(os.path.dirname(GOLDEN), exist_ok=True)
        with open(GOLDEN, "w", encoding="utf-8", newline="\n") as f:
            json.dump(got, f, indent=1)
            f.write("\n")
        pytest.skip("golden file written")
    with open(GOLDEN, encoding="utf-8") as f:
        assert got == json.load(f)


@pytest.mark.parametrize("obj, user", [("g_table", "dispatch"), ("g_n1", "walk"), ("g_bss", "fill_bss"), ("g_split", "split_leaf")])
def test_referenced_object_is_whole(db, obj, user):
    ea = db.ea(obj)
    # Each object here ends at the next symbol or at the end of its segment.
    end = min([a for a, _ in idautils.Names() if a > ea] + [ida_segment.getseg(ea).end_ea])
    assert ida_bytes.get_item_size(ea) < end - ea, "IDA typed the whole object, so this case goes untested"
    assert coverage(idaslicer.collect_function_ranges(db.ea(user))).covers(ea, end)


@pytest.mark.parametrize(
    "obj, limit, end",
    [
        ("g_table", 0, "g_table+0x8"),
        ("g_table", 4, "g_table+0x8"),
        ("g_table", 128, "g_n2"),
        ("g_counter", 128, "g_unused"),
        # No value, no limit.
        ("g_bss", 16, "g_split"),
    ],
)
def test_data_target_range(db, obj, limit, end):
    r = idaslicer._data_target_range(db.ea(obj), limit)
    assert (db.label(r.start_ea), db.label(r.end_ea)) == (obj, end)


def test_data_pointers(db):
    table = db.ea("g_table")
    assert idaslicer._data_pointers(table, table + 16, 8) == {db.ea("via_ptr"): table, db.ea("via_ptr2"): table + 8}
    bss = ida_segment.getseg(db.ea("g_bss"))
    assert idaslicer._data_pointers(bss.start_ea, bss.end_ea, 8) == {}


@pytest.fixture
def raw_table(db):
    """g_table undefined: its pointers are raw values IDA keeps no xref for."""
    table = db.ea("g_table")
    slots = (table, table + 8)
    flags = [ida_bytes.get_flags(a) for a in slots]
    assert ida_bytes.del_items(table, ida_bytes.DELIT_SIMPLE, 16)
    assert not [x for a in range(table, table + 16) for x in idautils.XrefsFrom(a, ida_xref.XREF_DATA)]
    yield table
    for a in slots:
        ida_fixup.del_fixup(a)
        assert ida_bytes.create_data(a, ida_bytes.FF_QWORD, 8, idaslicer.idaapi.BADADDR)
        assert ida_offset.op_plain_offset(a, 0, 0)
    assert [ida_bytes.get_flags(a) for a in slots] == flags


def test_raw_pointers_without_fixups(db, raw_table):
    assert idaslicer._data_pointers(raw_table, raw_table + 16, 8) == {db.ea("via_ptr"): raw_table, db.ea("via_ptr2"): raw_table + 8}


def test_raw_pointers_need_fixups_where_the_segment_has_them(db, raw_table):
    fixup = ida_fixup.fixup_data_t(ida_fixup.FIXUP_OFF64)
    fixup.off = db.ea("via_ptr2")
    ida_fixup.set_fixup(raw_table + 8, fixup)
    assert idaslicer._data_pointers(raw_table, raw_table + 16, 8) == {db.ea("via_ptr2"): raw_table + 8}


def test_loose_bss_stops_at_reference(db):
    start = db.ea("g_split")
    assert ida_xref.add_dref(db.ea("split_leaf"), start + 0x40, ida_xref.dr_O)
    try:
        assert idaslicer.get_loose_data_range(start, 16).end_ea == start + 0x40
    finally:
        ida_xref.del_dref(db.ea("split_leaf"), start + 0x40)


def test_loose_data_with_values_keeps_cap(db):
    ea = db.ea("g_counter")
    size, kind = ida_bytes.get_item_size(ea), ida_bytes.get_flags(ea) & ida_bytes.DT_TYPE
    assert ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
    try:
        assert idaslicer.get_loose_data_range(ea, 2).end_ea == ea + 2
    finally:
        assert ida_bytes.create_data(ea, kind, size, idaslicer.idaapi.BADADDR)


def test_loose_data_stops_at_code(db):
    ea = db.ea("uncalled")
    assert ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 4)
    try:
        r = idaslicer.get_loose_data_range(ea, 128)
        assert (r.start_ea, r.end_ea) == (ea, ea + 4)
    finally:
        assert ida_ua.create_insn(ea)


def test_from_range_seeds_code(db):
    s, e = db.ea("dispatch"), db.ea("walk")
    ranges = idaslicer.collect_recursive_ranges_from_range(s, e)
    assert (s, e) in ranges
    assert db.covered(ranges, SYMBOLS) == {"dispatch", "g_table", "via_ptr", "via_ptr2"}


def test_from_ranges_seeds_data(db):
    s = db.ea("g_table")
    # A pointer table as a loose seed: both entries lead to functions.
    ranges = idaslicer.collect_recursive_ranges_from_ranges([(s, s + 16), (s, s)])
    assert db.covered(ranges, SYMBOLS) == {"g_table", "via_ptr", "via_ptr2"}


def test_skip_named_data(db, monkeypatch):
    monkeypatch.setitem(idaslicer.SETTINGS, "skip_named_data", True)
    assert db.covered(idaslicer.collect_function_ranges(db.ea("walk")), SYMBOLS) == {"walk"}


def test_cancel_keeps_partial_result(db, monkeypatch):
    # A clock that jumps a second per call lifts the 0.1 s throttle on UI polls.
    clock = itertools.count(step=1.0)
    monkeypatch.setattr(idaslicer, "time", types.SimpleNamespace(monotonic=lambda: next(clock)))
    monkeypatch.setattr(idaslicer, "_last_cancel_check", float("-inf"))
    polls = itertools.count()
    monkeypatch.setattr(idaslicer.ida_kernwin, "user_cancelled", lambda: next(polls) < 0)
    full = idaslicer.collect_recursive_ranges(db.ea("root"))
    total = next(polls)

    polls = itertools.count()
    monkeypatch.setattr(idaslicer.ida_kernwin, "user_cancelled", lambda: next(polls) >= total * 2 // 3)
    with pytest.raises(idaslicer.ScanCancelled) as info:
        idaslicer.collect_recursive_ranges(db.ea("root"))
    partial = info.value.ranges
    assert partial and len(partial) < len(full)
    assert set(partial) <= set(full)


@pytest.mark.parametrize(
    "start, expected",
    [
        ("leaf", ["leaf", "callee_a", "fill_bss", "root", "_start", "split_entry"]),
        # Through g_table, which only data points at via_ptr from.
        ("via_ptr", ["via_ptr", "dispatch", "root", "_start", "split_entry"]),
        ("g_counter", ["leaf", "callee_a", "fill_bss", "root", "_start", "split_entry"]),
        ("uncalled", ["uncalled"]),
    ],
)
def test_caller_cluster(db, start, expected):
    assert [db.label(ea) for ea in idaslicer.get_caller_cluster(db.ea(start))] == expected


def test_recursive_from_callers(db):
    got = db.covered(idaslicer.collect_recursive_ranges_from_callers(db.ea("via_ptr")), SYMBOLS)
    assert got == set(SYMBOLS) - {"uncalled", "g_unused"}


def test_caller_cluster_through_code_no_function_owns(db, leaf_undefined):
    assert [db.label(ea) for ea in idaslicer.get_caller_cluster(leaf_undefined)][:3] == ["leaf", "callee_a", "fill_bss"]


@pytest.fixture
def leaf_undefined(db):
    """`leaf` with its function deleted, as IDA leaves obfuscated code."""
    ea = db.ea("leaf")
    assert ida_funcs.del_func(ea)
    yield ea
    assert ida_funcs.add_func(ea)


def test_reconstruct_func_range(db, leaf_undefined):
    assert idaslicer.reconstruct_func_range(leaf_undefined) == [(leaf_undefined, db.ea("callee_a"))]


def test_function_only_without_ida_function(db, leaf_undefined):
    assert db.covered(idaslicer.collect_function_ranges(leaf_undefined), SYMBOLS) == {"leaf", "g_counter"}


def test_recursive_reaches_code_no_function_owns(db, leaf_undefined):
    got = db.covered(idaslicer.collect_recursive_ranges(db.ea("callee_a")), SYMBOLS)
    assert got == {"callee_a", "leaf", "g_counter"}


@pytest.fixture
def callee_a_cut(db):
    """callee_a ending right after its call to leaf, as if its end had been set
    by hand: (start, the cut, the real end)."""
    start = db.ea("callee_a")
    end = ida_funcs.get_func(start).end_ea
    call = next(h for h in idautils.FuncItems(start) if any(x.type == ida_xref.fl_CN for x in idautils.XrefsFrom(h, ida_xref.XREF_FAR)))
    cut = ida_bytes.get_item_end(call)
    assert cut < end and ida_funcs.set_func_end(start, cut)
    yield start, cut, end
    ida_funcs.del_func(cut)
    assert ida_funcs.set_func_end(start, end)


def test_fall_through_into_code_no_function_owns(db, callee_a_cut):
    start, _, end = callee_a_cut
    assert coverage(idaslicer.collect_function_ranges(start)).covers(start, end)


def test_no_fall_through_after_call_into_function(db, callee_a_cut):
    start, cut, _ = callee_a_cut
    assert ida_funcs.add_func(cut)
    got = coverage(idaslicer.collect_function_ranges(start))
    assert got.covers(start, cut) and not got.covers(cut, cut + 1)
