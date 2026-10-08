import ida_funcs
import idautils
import pytest
from invariants import check_own_in_recursive, check_scan, coverage

import idaslicer


@pytest.fixture
def split_leaf(stripped_db):
    """split_leaf as IDA split it: (the lone nop, the end of the rest)."""
    ea = stripped_db.ea("split_leaf")
    assert ida_funcs.get_func(ea).end_ea == ea + 4, "IDA no longer splits split_leaf, so this case goes untested"
    rest = ida_funcs.get_func(ea + 4)
    assert rest.start_ea == ea + 4
    return ea, rest.end_ea


def test_function_only_follows_fall_through(stripped_db, split_leaf):
    start, end = split_leaf
    got = coverage(idaslicer.collect_function_ranges(start))
    assert got.covers(start, end)
    assert got.covers(stripped_db.ea("g_split"), stripped_db.ea("g_split") + 1)


def test_recursive_follows_fall_through(stripped_db, split_leaf):
    start, end = split_leaf
    origins = {}
    got = coverage(idaslicer.collect_recursive_ranges(stripped_db.ea("split_entry"), origins))
    assert got.covers(start, end)
    assert got.covers(stripped_db.ea("g_split"), stripped_db.ea("g_split") + 1)
    assert origins[start + 4] == start


def test_caller_cluster_follows_fall_through(stripped_db, split_leaf):
    start, _ = split_leaf
    assert idaslicer.get_caller_cluster(start + 4) == [start + 4, start, stripped_db.ea("split_entry")]


def test_scan_invariants_for_every_function(stripped_db):
    for ea in idautils.Functions():
        for collect in (idaslicer.collect_recursive_ranges, idaslicer.collect_function_ranges):
            origins = {}
            check_scan(stripped_db, ea, collect(ea, origins), origins)
        check_own_in_recursive(stripped_db, ea)
