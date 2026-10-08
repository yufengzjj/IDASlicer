import json
import os

import ida_loader
import ida_nalt
import ida_segment

import idaslicer


def _rows(db, entries):
    return [f"{db.label(e.start)}..{db.label(e.end)}" for e in entries]


def _entry(start, end, name="hand"):
    seg = ida_segment.getseg(start)
    return idaslicer.SlicerEntry(name, start, end, seg.perm, seg.type, seg.align)


def test_recursive_add_merges_into_runs(db, plugin):
    origins = {}
    ranges = idaslicer.collect_recursive_ranges(db.ea("root"), origins)
    added, extended = plugin._add_collected_ranges(ranges, origins)
    assert (added, extended) == (len(plugin.entries), 0)
    assert _rows(db, plugin.entries) == [
        "g_msg..g_msg+0x10",
        "leaf..uncalled",
        "root.._start",
        "g_counter..g_unused",
        "g_table..g_bss",
        "g_bss..g_split",
    ]
    by_start = {db.label(e.start): e for e in plugin.entries}
    assert by_start["leaf"].name == f"leaf_{db.ea('leaf'):#x}"
    assert by_start["leaf"].ref == origins[db.ea("leaf")]
    assert by_start["root"].ref is None
    assert all(e.recursive for e in plugin.entries)
    assert by_start["root"].perm == ida_segment.getseg(db.ea("root")).perm

    # The same discovery again lands inside existing rows.
    assert plugin._add_collected_ranges(ranges, origins) == (0, 0)


def test_discovery_extends_or_replaces(db, plugin):
    leaf, callee = db.ea("leaf"), db.ea("callee_a")
    plugin.entries = [_entry(leaf, callee, "mine")]
    assert plugin._add_collected_ranges([(callee, db.ea("via_ptr"))]) == (0, 1)
    assert [(e.name, db.label(e.end)) for e in plugin.entries] == [("mine", "via_ptr")]

    # A run that starts before an existing entry takes its place.
    plugin.entries = [_entry(callee, db.ea("via_ptr"), "mine")]
    assert plugin._add_collected_ranges([(leaf, callee)], recursive=False) == (1, 0)
    assert [(db.label(e.start), db.label(e.end), e.recursive) for e in plugin.entries] == [("leaf", "via_ptr", False)]


def test_runs_stay_apart_at_segment_start(db, plugin):
    bss = ida_segment.getseg(db.ea("g_bss")).start_ea
    plugin._add_collected_ranges([(db.ea("g_n1"), bss), (bss, bss + 16)])
    assert _rows(db, plugin.entries) == ["g_n1..g_bss", "g_bss..g_bss+0x10"]


def test_hand_adds_merge_only_overlaps(db, plugin):
    leaf, callee, via = db.ea("leaf"), db.ea("callee_a"), db.ea("via_ptr")
    plugin.add_to_list(_entry(leaf, callee), _entry(callee, via))
    assert _rows(db, plugin.entries) == ["leaf..callee_a", "callee_a..via_ptr"]
    # Overlapping both rows bridges them.
    plugin.add_to_list(_entry(leaf + 4, callee + 4))
    assert _rows(db, plugin.entries) == ["leaf..via_ptr"]


def test_export_entries_leaves_list_alone(db):
    leaf, callee, via = db.ea("leaf"), db.ea("callee_a"), db.ea("via_ptr")
    entries = [_entry(leaf, callee), _entry(leaf + 4, callee + 4), _entry(callee + 4, via), _entry(via, via)]
    out = idaslicer._export_entries(entries)
    assert _rows(db, out) == ["leaf..callee_a+0x4", "callee_a+0x4..via_ptr"]
    assert _rows(db, entries) == ["leaf..callee_a", "leaf+0x4..callee_a+0x4", "callee_a+0x4..via_ptr", "via_ptr..via_ptr"]
    assert out[0].sig != entries[0].sig


def test_display_name_demangles_the_symbol(db):
    shown = "std::bad_array_new_length::bad_array_new_length(void)"
    assert idaslicer._display_name("_ZNSt20bad_array_new_lengthC2Ev_0x1000", 0x1000) == shown + "_0x1000"
    assert idaslicer._display_name("_ZNSt20bad_array_new_lengthC2Ev", 0x1000) == shown
    assert idaslicer._display_name("leaf_0x1000", 0x1000) == "leaf_0x1000"
    # A suffix that is not this entry's start is part of the name, as typed.
    assert idaslicer._display_name("_ZNSt20bad_array_new_lengthC2Ev_0x2000", 0x1000) == "_ZNSt20bad_array_new_lengthC2Ev_0x2000"


def test_slicer_list_lives_next_to_the_database(db, plugin, tmp_path):
    config, listed = tmp_path / "idaslicer_config.json", tmp_path / "db.slicer.json"
    other = {"entries": {"other": [{"name": "x", "start": 1, "end": 2}]}}
    config.write_text(json.dumps(other))
    plugin.load_config()
    assert plugin.entries == []
    assert plugin.save_entries() and not listed.exists(), "no file for an empty list"
    plugin.entries = [_entry(db.ea("leaf"), db.ea("callee_a"), "mine")]
    assert plugin.save_entries()
    plugin.entries = []
    plugin.load_config()
    assert [(e.name, e.start, e.end) for e in plugin.entries] == [("mine", db.ea("leaf"), db.ea("callee_a"))]
    assert json.loads(config.read_text()) == other
    plugin.save_settings()
    saved = json.loads(config.read_text())
    assert saved["entries"] == other["entries"] and saved["settings"] == idaslicer.SETTINGS
    idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    assert os.path.normcase(idb) == os.path.normcase(f"{db.path}.i64")
    assert os.path.normcase(idaslicer._slicer_list_path()) == os.path.normcase(f"{db.path}.slicer.json")


def test_old_list_moves_out_of_the_config(db, plugin, tmp_path):
    config, listed = tmp_path / "idaslicer_config.json", tmp_path / "db.slicer.json"
    md5 = ida_nalt.retrieve_input_file_md5().hex()
    old = _entry(db.ea("leaf"), db.ea("callee_a"), "old").to_dict()
    config.write_text(json.dumps({"entries": {md5: [old], "other": []}, "last_import_path": "C:/seg"}))
    plugin.load_config()
    assert [e.name for e in plugin.entries] == ["old"]
    assert json.loads(listed.read_text())["entries"] == [old]
    assert json.loads(config.read_text()) == {"entries": {"other": []}, "last_import_path": "C:/seg"}
    plugin.entries = []
    plugin.load_config()
    assert [e.name for e in plugin.entries] == ["old"]
