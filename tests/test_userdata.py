import json
import os
import shutil
import time

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_nalt
import ida_name
import ida_pro
import ida_segment
import ida_typeinf
import idautils
import idc
import pytest
import userdata_child

import idaslicer

BADADDR = ida_idaapi.BADADDR


def _local_label():
    for ea in idautils.Heads():
        pfn = ida_funcs.get_func(ea)
        if pfn and pfn.start_ea != ea and ida_bytes.has_dummy_name(ida_bytes.get_flags(ea)):
            return ea
    raise AssertionError("the sample has no loc_ label inside a function")


def _calls(func_ea):
    pfn = ida_funcs.get_func(func_ea)
    return [ea for ea in idautils.Heads(pfn.start_ea, pfn.end_ea) if ida_idp.is_call_insn(ea)]


def _lvar_names(ea):
    ida_hexrays.mark_cfunc_dirty(ea)
    hf = ida_hexrays.hexrays_failure_t()
    cf = ida_hexrays.decompile(ea, hf)
    assert cf is not None, hf.desc()
    return [v.name for v in cf.get_lvars()]


@pytest.fixture(scope="module")
def edits(db):
    """One user edit of every kind the export covers."""
    assert ida_hexrays.init_hexrays_plugin(), "the tests need the arm64 decompiler"
    e = {name: db.ea(name) for name in ("root", "leaf", "walk", "g_n1", "g_msg")}
    decls = (
        "struct Node { Node *next; int v; }; struct Unused { int u; };"
        "enum Kind { KIND_A }; struct Leaf { int x; }; struct Inner { Leaf leaf; Kind kind; }; struct Tail { int t; };"
        "struct Payload { int a; Inner *in; Tail *tails[2]; }; typedef Payload *PayloadRef;"
    )
    assert ida_typeinf.parse_decls(None, decls, None, ida_typeinf.HTI_DCL) == 0

    e["original"] = ida_bytes.get_bytes(e["g_msg"], 5)
    ida_bytes.patch_bytes(e["g_msg"], b"HELLO")
    e["call"], e["udcall"] = _calls(e["root"])[:2]
    # What pressing Y on a call instruction does; it reports failure but sets the type.
    idc.SetType(e["call"], "int __fastcall f(PayloadRef x);")
    assert ida_nalt.is_userti(e["call"])

    assert ida_name.set_name(e["leaf"], "my_leaf", ida_name.SN_NOCHECK)
    e["label"] = _local_label()
    assert ida_name.set_name(e["label"], "my_label", ida_name.SN_LOCAL)

    proto = idaslicer._parse_type("int __fastcall f(Node *head, int count);")
    assert ida_typeinf.apply_tinfo(e["walk"], proto, ida_typeinf.TINFO_DEFINITE)
    assert ida_typeinf.apply_tinfo(e["g_n1"], idaslicer._parse_type("Node x;"), ida_typeinf.TINFO_DEFINITE)

    assert ida_funcs.set_func_cmt(ida_funcs.get_func(e["leaf"]), "leaf comment", True)
    idc.put_bookmark(e["leaf"], 0, 0, 0, 3, "look here")

    lvars = ida_hexrays.decompile(e["root"]).get_lvars()
    assert ida_hexrays.rename_lvar(e["root"], lvars[0].name, "count")
    cf = ida_hexrays.decompile(e["root"])
    loc = ida_hexrays.treeloc_t()
    loc.ea, loc.itp = cf.body.cblock[0].ea, ida_hexrays.ITP_SEMI
    cf.set_user_cmt(loc, "pseudocode comment")
    cf.save_user_cmts()
    labels = ida_hexrays.user_labels_new()
    ida_hexrays.user_labels_insert(labels, 5, "hr_label")
    ida_hexrays.save_user_labels(e["root"], labels)
    numforms = ida_hexrays.user_numforms_new()
    fmt = ida_hexrays.number_format_t()
    fmt.flags = ida_bytes.dec_flag()
    ida_hexrays.user_numforms_insert(numforms, ida_hexrays.operand_locator_t(e["root"], 0), fmt)
    ida_hexrays.save_user_numforms(e["root"], numforms)
    iflags = ida_hexrays.user_iflags_new()
    ida_hexrays.user_iflags_insert(iflags, ida_hexrays.citem_locator_t(e["root"], ida_hexrays.cot_add), 1)
    ida_hexrays.save_user_iflags(e["root"], iflags)
    unions = ida_hexrays.user_unions_new()
    path = ida_pro.intvec_t()
    path.push_back(1)
    ida_hexrays.user_unions_insert(unions, e["root"], path)
    ida_hexrays.save_user_unions(e["root"], unions)
    calls = ida_hexrays.udcall_map_new()
    call = ida_hexrays.udcall_t()
    assert ida_hexrays.parse_user_call(call, "int __fastcall dispatch(int i, int a);", True)
    ida_hexrays.udcall_map_insert(calls, e["udcall"], call)
    ida_hexrays.save_user_defined_calls(e["root"], calls)
    ida_hexrays.mark_cfunc_dirty(e["root"])
    return e


def test_export_keeps_only_user_edits(edits):
    data = idaslicer.export_user_data()
    names = {ea: (name, local) for ea, name, local in data["names"]}
    assert names[edits["leaf"]] == ("my_leaf", False)
    assert names[edits["label"]] == ("my_label", True)
    assert names[edits["root"]] == ("root", False)  # symbols are not IDA's own names either
    assert not [n for n, _ in names.values() if n.startswith(("sub_", "loc_", "dword_", "off_", "unk_"))]
    assert data["patches"] == [[edits["g_msg"], edits["original"].hex(), b"HELLO".hex()]]
    assert {ea for ea, _ in data["applied_types"]} == {edits["walk"], edits["g_n1"], edits["call"]}
    assert data["func_comments"] == [[edits["leaf"], True, "leaf comment"]]
    assert data["bookmarks"] == [[3, edits["leaf"], "look here"]]
    # Only the call type names PayloadRef; the rest of its chain comes from the types themselves.
    chain = {"typedef Payload *PayloadRef;", "struct Payload", "struct Inner", "struct Tail", "struct Leaf", "enum Kind"}
    assert {"struct Node"} | chain <= _type_heads(data)
    assert not any("Unused" in line or "short float" in line for line in data["types"])
    (root_hr,) = [f for f in data["decompiler"] if f["ea"] == edits["root"]]
    assert "count" in [v["name"] for v in root_hr["lvars"]["vars"]]
    assert {"comments", "labels", "numforms", "iflags", "unions"} <= root_hr.keys()
    assert [cea for cea, _, _ in root_hr["calls"]] == [edits["udcall"]]
    assert data["not_exported"] == []


def _type_heads(data):
    return {block.splitlines()[0] for block in idaslicer._type_blocks(data["types"])}


def test_export_all_types(edits, monkeypatch):
    every = idaslicer.export_user_data(all_types=True)
    assert "struct Unused" in _type_heads(every)
    assert any("short float" in line for line in every["types"])
    monkeypatch.setitem(idaslicer.SETTINGS, "export_all_types", True)
    assert idaslicer.export_user_data() == every


def test_export_limited_to_ranges(edits):
    leaf, root = ida_funcs.get_func(edits["leaf"]), edits["root"]
    # root's own start lies outside, so root is not exported.
    ranges = idaslicer._merge_intervals([(leaf.start_ea, leaf.end_ea), (edits["g_msg"], edits["g_msg"] + 16), (root + 4, root + 8)])
    full, part = idaslicer.export_user_data(), idaslicer.export_user_data(ranges=ranges)
    inside = lambda ea: any(s <= ea < e for s, e in ranges)
    assert [edits["leaf"], "my_leaf", False] in part["names"]
    assert part["names"] == [n for n in full["names"] if inside(n[0])]
    assert part["applied_types"] == [t for t in full["applied_types"] if inside(t[0])]
    assert part["patches"] == full["patches"] != []
    assert part["functions"] == [[leaf.start_ea, leaf.end_ea]]
    assert part["func_comments"] == full["func_comments"] != []
    assert part["bookmarks"] == full["bookmarks"] != []
    assert part["decompiler"] == [f for f in full["decompiler"] if f["ea"] == leaf.start_ea]


def test_panel_exports_the_listed_ranges(edits, plugin, qt, tmp_path):
    plugin.export_analysis(True)
    assert [c[:2] for c in qt.box.calls] == [("warning", "Nothing to export")]
    origins = {}
    plugin._add_collected_ranges(idaslicer.collect_function_ranges(edits["leaf"], origins), origins, recursive=False)
    path = tmp_path / "ranges.json"
    qt.files.files = [str(path)]
    plugin.export_analysis(True)
    assert qt.box.calls[-1][:2] == ("information", "Analysis exported"), qt.box.calls
    count = len(idaslicer._merge_intervals((e.start, e.end) for e in plugin.entries))
    assert f"Only what lies in {count} ranges of the slicer list -- not a full backup" in qt.box.calls[-1][2]
    data = idaslicer.load_user_data(str(path))
    assert [start for start, _ in data["functions"]] == [edits["leaf"]]


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="create_struct (Alt+Q) stores no type at the address, so no is_userti")
def test_struct_var_on_data_is_exported(edits, db):
    ea = db.ea("g_n2")
    tid = ida_typeinf.get_named_type_tid("Node")
    size = ida_typeinf.tinfo_t(tid=tid).get_size()
    # A length of -1 ("the struct's size") fails on IDA 9.5.
    if not ida_bytes.create_struct(ea, size, tid, True) or not ida_bytes.is_struct(ida_bytes.get_flags(ea)):
        pytest.fail("create_struct did not make a struct item")
    try:
        assert ea in {a for a, _ in idaslicer.export_user_data()["applied_types"]}
    finally:
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)


def _wipe(e):
    """Undo or overwrite every edit, the way a rebuilt database lacks them."""
    for i in range(len(e["original"])):
        ida_bytes.revert_byte(e["g_msg"] + i)
    ida_nalt.del_tinfo(e["call"])
    ida_hexrays.save_user_defined_calls(e["root"], ida_hexrays.udcall_map_new())
    ida_name.set_name(e["leaf"], "other_leaf", ida_name.SN_NOCHECK)
    ida_name.del_local_name(e["label"])
    ida_nalt.del_tinfo(e["walk"])
    ida_nalt.del_tinfo(e["g_n1"])
    ida_funcs.set_func_cmt(ida_funcs.get_func(e["leaf"]), "changed", True)
    ida_typeinf.parse_decls(None, "struct Node { int other; };", None, ida_typeinf.HTI_DCL)
    ida_hexrays.rename_lvar(e["root"], "count", "renamed")
    for kind in ("cmts", "labels", "numforms", "iflags", "unions"):
        getattr(ida_hexrays, f"save_user_{kind}")(e["root"], getattr(ida_hexrays, f"user_{kind}_new")())
    ida_hexrays.mark_cfunc_dirty(e["root"])


@pytest.mark.parametrize("all_types", [False, True])
def test_import_restores_every_edit(edits, all_types):
    before = idaslicer.export_user_data(all_types)
    # IDA prints the decompiler's ARM SVE types with `short float`, which its own
    # parser rejects; re-parsing them would damage them.
    assert any("short float" in line for line in before["types"]) == all_types
    _wipe(edits)
    assert idaslicer.export_user_data(all_types) != before
    done, problems = idaslicer.import_user_data(json.loads(idaslicer.format_user_data(before)))
    assert problems == []
    assert done["name"] == len(before["names"])
    # Node, and with only referenced types also the forward declarations they open with.
    assert done["local type"] == (1 if all_types else 2)
    assert idaslicer.export_user_data(all_types) == before
    assert "count" in _lvar_names(edits["root"])


def _json(data):
    return json.loads(json.dumps(data))


def test_import_into_a_rebuilt_database(edits, sample_elf, tmp_path):
    """The real use: the binary analysed again from scratch, then the export imported."""
    before = idaslicer.export_user_data()
    exported = tmp_path / "export.json"
    exported.write_text(idaslicer.format_user_data(before), encoding="utf-8")
    binary = tmp_path / sample_elf.name
    shutil.copy(sample_elf, binary)
    result = userdata_child.run(binary, tmp_path / "out.json", import_path=exported)
    assert result["problems"] == []
    after, before = result["export"], _json(before)
    # Ordinals follow the order types were added in, which differs.
    assert set(idaslicer._type_blocks(after.pop("types"))) == set(idaslicer._type_blocks(before.pop("types")))
    assert after == before


_SLICE_EDITS = """
import ida_auto, ida_bytes, ida_funcs, ida_hexrays, ida_name, ida_typeinf
for ea in {funcs}:
    ida_funcs.add_func(ea)
ida_auto.auto_wait()
ida_name.set_name({callee}, "slice_callee", ida_name.SN_NOCHECK)
ida_funcs.set_func_cmt(ida_funcs.get_func({callee}), "from the slice", False)
ida_typeinf.parse_decls(None, "struct SliceS {{ int a; int b; }};", None, ida_typeinf.HTI_DCL)
ida_typeinf.apply_tinfo({via}, idaslicer._parse_type("int __fastcall f(SliceS *s);"), ida_typeinf.TINFO_DEFINITE)
assert ida_hexrays.init_hexrays_plugin()
arg = next(v for v in ida_hexrays.decompile({fill}).get_lvars() if v.is_arg_var)
assert ida_hexrays.rename_lvar({fill}, arg.name, "slice_var")
ida_hexrays.mark_cfunc_dirty({fill})
assert "slice_var" in str(ida_hexrays.decompile({fill}))
"""


def test_edits_made_in_a_slice_go_back_to_the_source(edits, db, plugin, qt, tmp_path):
    """Work on a small slice of a big binary, then carry the analysis back."""
    before = idaslicer.export_user_data()
    origins = {}
    plugin._add_collected_ranges(idaslicer.collect_recursive_ranges(db.ea("root"), origins), origins)
    plugin.perform_slice(plugin.entries, plugin.detect_file_type())
    assert qt.box.calls[-1][:2] == ("information", "Success"), qt.box.calls
    sliced = db.path.with_name(db.path.stem + "_slice.i64")
    funcs = [f for f in idautils.Functions() if any(e.start <= f < e.end for e in plugin.entries)]
    callee, via, fill = db.ea("callee_a"), db.ea("via_ptr2"), db.ea("fill_bss")
    assert {callee, via, fill} <= set(funcs)
    script = tmp_path / "edits.py"
    script.write_text(_SLICE_EDITS.format(funcs=funcs, callee=callee, via=via, fill=fill), encoding="utf-8")
    from_slice = userdata_child.run(sliced, tmp_path / "out.json", script=script)["export"]

    _, problems = idaslicer.import_user_data(from_slice)
    assert problems == []
    assert ida_name.get_ea_name(callee, 0) == "slice_callee"
    assert ida_funcs.get_func_cmt(ida_funcs.get_func(callee), False) == "from the slice"
    assert "SliceS" in idaslicer._applied_type(via)
    assert "slice_var" in _lvar_names(fill)

    after = _json(idaslicer.export_user_data())
    before = _json(before)
    for key in ("patches", "functions", "bookmarks"):
        assert after[key] == before[key], key
    names = lambda d: {tuple(n) for n in d["names"]}
    assert names(after) - names(before) == {(callee, "slice_callee", False)}
    assert names(before) - names(after) == {(callee, "callee_a", False)}
    assert [c for c in after["func_comments"] if c not in before["func_comments"]] == [[callee, False, "from the slice"]]
    assert [t for t in after["applied_types"] if t not in before["applied_types"]] == [[via, idaslicer._applied_type(via)]]
    others = lambda d: [f for f in d["decompiler"] if f["ea"] != fill]
    assert others(after) == others(before)


def _as_old_slice(data):
    """What a slice made before slices kept their source's image base exports:
    the source's addresses, and the template's image base of 0."""
    return {**_json(data), "imagebase": 0}


def test_old_slice_export_keeps_its_addresses(edits):
    assert ida_nalt.get_imagebase() != 0, "the sample must not load at 0, or there is nothing to tell apart"
    before = idaslicer.export_user_data()
    old = _as_old_slice(before)
    assert idaslicer.shift_by_image_base(old) is False
    assert idaslicer.shift_by_image_base({**old, "functions": []}) is None
    _wipe(edits)
    _, problems = idaslicer.import_user_data(old, shift=False)
    assert problems == []
    assert {**idaslicer.export_user_data(), "imagebase": 0} == {**before, "imagebase": 0}


def test_panel_asks_when_functions_do_not_tell(edits, plugin, qt, tmp_path):
    old = _as_old_slice(idaslicer.export_user_data())
    old["functions"] = []
    path = tmp_path / "old_slice.json"
    path.write_text(idaslicer.format_user_data(old), encoding="utf-8")
    qt.files.files = [str(path)]
    qt.box.answers["question"] = "No"
    ida_auto.auto_wait()
    plugin.import_analysis()
    assert [c[:2] for c in qt.box.calls] == [("question", "Image base differs"), ("information", "Analysis imported")]
    assert "addresses kept" in qt.box.calls[-1][2]
    assert "could not be applied" not in qt.box.calls[-1][2]


def test_import_follows_a_new_image_base(edits):
    before = idaslicer.export_user_data()
    delta = 0x100000
    assert ida_segment.rebase_program(delta, ida_segment.MSF_FIXONCE) == 0
    moved = {k: v if isinstance(v, bytes) else v + delta for k, v in edits.items()}
    _wipe(moved)
    assert idaslicer.shift_by_image_base(before) is True
    _, problems = idaslicer.import_user_data(before)
    assert problems == []
    assert ida_name.get_ea_name(moved["leaf"], 0) == "my_leaf"
    assert ida_bytes.get_bytes(moved["g_msg"], 5) == b"HELLO"
    assert ida_funcs.get_func_cmt(ida_funcs.get_func(moved["leaf"]), True) == "leaf comment"
    assert idc.get_bookmark(3) == moved["leaf"]
    assert "count" in _lvar_names(moved["root"])


def test_format_round_trips():
    data = {"format": "x", "empty": [], "none": None, "rows": [[1, "ü\n", True], {"a": [1]}], "lines": ["struct A", "{"]}
    text = idaslicer.format_user_data(data)
    assert json.loads(text) == data
    assert '  [1, "ü\\n", true],\n' in text


@pytest.mark.parametrize("content", ["[]", '{"format": "other"}', '{"format": "idaslicer-userdata", "version": 99}', "not json"])
def test_load_rejects(tmp_path, content):
    path = tmp_path / "x.json"
    path.write_text(content)
    with pytest.raises(ValueError):
        idaslicer.load_user_data(str(path))


def test_save_rotating(tmp_path, monkeypatch):
    clock = iter(f"20260101-0000{s:02d}" for s in range(60))
    monkeypatch.setattr(idaslicer.time, "strftime", lambda fmt: next(clock))
    folder = str(tmp_path / "a.userdata")
    first = idaslicer.save_rotating(folder, "one", keep=2)
    assert idaslicer.save_rotating(folder, "one", keep=2) is None
    idaslicer.save_rotating(folder, "two", keep=2)
    last = idaslicer.save_rotating(folder, "three", keep=2)
    (tmp_path / "a.userdata" / "notes.txt").write_text("mine")
    assert sorted(os.listdir(folder)) == ["20260101-000001.json", "20260101-000002.json", "notes.txt"]
    assert not os.path.exists(first)
    with open(last, encoding="utf-8") as f:
        assert f.read() == "three"


def test_panel_export_then_import_asks_about_another_binary(edits, plugin, qt, tmp_path):
    path = tmp_path / "analysis.json"
    qt.files.files = [str(path)]
    plugin.export_analysis()
    assert qt.box.calls[-1][:2] == ("information", "Analysis exported"), qt.box.calls
    data = idaslicer.load_user_data(str(path))
    data["input_md5"] = "0" * 32
    path.write_text(idaslicer.format_user_data(data), encoding="utf-8")
    qt.box.answers["question"] = "No"
    plugin.import_analysis()
    assert [c[0] for c in qt.box.calls] == ["information", "question"]
    qt.box.answers["question"] = "Yes"
    plugin.import_analysis()
    assert qt.box.calls[-1][:2] == ("information", "Analysis imported")


def test_autosave_skips_an_unchanged_database(edits, plugin, tmp_path, monkeypatch):
    exports = []
    real_export = idaslicer.export_user_data

    def export():
        exports.append(1)
        if len(exports) == 3:
            raise OSError("disk full")
        return real_export()

    monkeypatch.setattr(idaslicer, "export_user_data", export)
    monkeypatch.setattr(idaslicer, "_autosave_dir", lambda: str(tmp_path / "a.userdata"))
    monkeypatch.setitem(idaslicer.SETTINGS, "autosave_minutes", 1)
    # Not hooked: `changed` is set by hand.
    plugin._changes = idaslicer._ChangeTracker()
    ida_auto.auto_wait()

    def tick():
        plugin._last_autosave = time.monotonic() - 3600
        plugin._autosave_tick()
        return len(exports)

    assert tick() == 1
    assert tick() == 1
    # By name: an earlier test moved the image base.
    assert ida_hexrays.rename_lvar(ida_name.get_name_ea(BADADDR, "root"), "count", "autosaved_var")
    assert tick() == 2, "a decompiler edit made through the API raises no event"
    assert tick() == 2
    plugin._changes.changed = True
    assert tick() == 3 and plugin._changes.changed, "a failed export must be retried"


def test_change_tracker_notes_every_kind_of_edit(edits):
    root, leaf, walk, msg = (ida_name.get_name_ea(BADADDR, n) for n in ("root", "my_leaf", "walk", "g_msg"))
    assert BADADDR not in (root, leaf, walk, msg)
    tracker = idaslicer._ChangeTracker()
    tracker.hook()
    try:
        tracker.changed = False
        idaslicer.export_user_data()
        assert not tracker.changed, "exporting must not count as a change"
        for kind, edit in [
            ("name", lambda: ida_name.set_name(leaf, "tracked_leaf", ida_name.SN_NOCHECK)),
            ("type", lambda: ida_typeinf.apply_tinfo(walk, idaslicer._parse_type("int __fastcall f(int a);"), ida_typeinf.TINFO_DEFINITE)),
            ("local type", lambda: ida_typeinf.parse_decls(None, "struct Tracked { int t; };", None, ida_typeinf.HTI_DCL)),
            ("patch", lambda: ida_bytes.patch_byte(msg, ord("J"))),
            ("function comment", lambda: ida_funcs.set_func_cmt(ida_funcs.get_func(leaf), "tracked", True)),
            ("function end", lambda: ida_funcs.set_func_end(leaf, ida_funcs.get_func(leaf).end_ea - 4)),
            ("bookmark", lambda: idc.put_bookmark(root, 0, 0, 0, 4, "tracked")),
        ]:
            tracker.changed = False
            edit()
            assert tracker.changed, kind
    finally:
        tracker.unhook()
