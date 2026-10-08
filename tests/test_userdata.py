import json
import os
import shutil

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_lines
import ida_nalt
import ida_name
import ida_pro
import ida_segment
import ida_typeinf
import ida_ua
import idautils
import idc
import pytest
import userdata_child

import idaslicer

BADADDR = ida_idaapi.BADADDR


def _insn(ea):
    insn = ida_ua.insn_t()  # ty:ignore[missing-argument]
    assert ida_ua.decode_insn(insn, ea) > 0
    return insn


def _operand(func_ea, optype):
    """The first (address, operand number) in the function whose operand has this type."""
    pfn = ida_funcs.get_func(func_ea)
    for ea in idautils.Heads(pfn.start_ea, pfn.end_ea):
        for n, op in enumerate(_insn(ea).ops):
            if op.type == optype:
                return ea, n
    raise AssertionError(f"no operand of type {optype} in {func_ea:#x}")


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
    e = {name: db.ea(name) for name in ("root", "leaf", "walk", "via_ptr2", "g_n1", "g_msg")}
    assert ida_typeinf.parse_decls(None, "struct Node { Node *next; int v; }; enum Mask { MASK_55 = 0x55 };", None, ida_typeinf.HTI_DCL) == 0

    e["original"] = ida_bytes.get_bytes(e["g_msg"], 5)
    ida_bytes.patch_bytes(e["g_msg"], b"HELLO")
    e["call"], e["udcall"] = _calls(e["root"])[:2]
    # What pressing Y on a call instruction does; it reports failure but sets the type.
    idc.SetType(e["call"], "int __fastcall f(int x);")
    assert ida_nalt.is_userti(e["call"])

    assert ida_name.set_name(e["leaf"], "my_leaf", ida_name.SN_NOCHECK)
    e["label"] = _local_label()
    assert ida_name.set_name(e["label"], "my_label", ida_name.SN_LOCAL)

    proto = idaslicer._parse_type("int __fastcall f(Node *head, int count);")
    assert ida_typeinf.apply_tinfo(e["walk"], proto, ida_typeinf.TINFO_DEFINITE)
    assert ida_typeinf.apply_tinfo(e["g_n1"], idaslicer._parse_type("Node x;"), ida_typeinf.TINFO_DEFINITE)

    assert ida_bytes.set_cmt(e["root"], "regular", False)
    assert ida_bytes.set_cmt(e["root"], "repeatable", True)
    ida_lines.update_extra_cmt(e["root"], ida_lines.E_PREV, "before 1")
    ida_lines.update_extra_cmt(e["root"], ida_lines.E_PREV + 1, "before 2")
    ida_lines.update_extra_cmt(e["root"], ida_lines.E_NEXT, "after")
    assert ida_funcs.set_func_cmt(ida_funcs.get_func(e["leaf"]), "leaf comment", True)

    e["stroff"] = _operand(e["walk"], ida_ua.o_displ)
    assert ida_bytes.op_stroff(_insn(e["stroff"][0]), e["stroff"][1], [ida_typeinf.get_named_type_tid("Node")], 0)
    e["enum"] = _operand(e["via_ptr2"], ida_ua.o_imm)
    assert ida_bytes.op_enum(*e["enum"], ida_typeinf.get_named_type_tid("Mask"), 0)
    e["forced"] = (e["root"], 0)
    assert ida_bytes.set_forced_operand(*e["forced"], "FORCED")

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
    assert [edits["root"], True, ["before 1", "before 2"]] in data["extra_comments"]
    assert [edits["root"], False, ["after"]] in data["extra_comments"]
    assert data["func_comments"] == [[edits["leaf"], True, "leaf comment"]]
    ops = {(ea, n): kind for ea, n, kind, *_ in data["operands"]}
    assert ops == {edits["stroff"]: "stroff", edits["enum"]: "enum", edits["forced"]: "forced"}
    assert data["bookmarks"] == [[3, edits["leaf"], "look here"]]
    assert any(line.startswith("struct Node") for line in data["types"])
    (root_hr,) = [f for f in data["decompiler"] if f["ea"] == edits["root"]]
    assert "count" in [v["name"] for v in root_hr["lvars"]["vars"]]
    assert {"comments", "labels", "numforms", "iflags", "unions"} <= root_hr.keys()
    assert [cea for cea, _, _ in root_hr["calls"]] == [edits["udcall"]]
    assert data["not_exported"] == []


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
    ida_bytes.set_cmt(e["root"], "", False)
    ida_bytes.set_cmt(e["root"], "", True)
    ida_lines.delete_extra_cmts(e["root"], ida_lines.E_PREV)
    ida_lines.delete_extra_cmts(e["root"], ida_lines.E_NEXT)
    ida_funcs.set_func_cmt(ida_funcs.get_func(e["leaf"]), "changed", True)
    for ea, n in (e["stroff"], e["enum"]):
        ida_bytes.clr_op_type(ea, n)
    ida_bytes.set_forced_operand(*e["forced"], "")
    ida_typeinf.parse_decls(None, "struct Node { int other; };", None, ida_typeinf.HTI_DCL)
    ida_hexrays.rename_lvar(e["root"], "count", "renamed")
    for kind in ("cmts", "labels", "numforms", "iflags", "unions"):
        getattr(ida_hexrays, f"save_user_{kind}")(e["root"], getattr(ida_hexrays, f"user_{kind}_new")())
    ida_hexrays.mark_cfunc_dirty(e["root"])


def test_import_restores_every_edit(edits):
    before = idaslicer.export_user_data()
    # IDA prints the decompiler's ARM SVE types with `short float`, which its own
    # parser rejects; re-parsing them would damage them.
    assert any("short float" in line for line in before["types"])
    _wipe(edits)
    assert idaslicer.export_user_data() != before
    done, problems = idaslicer.import_user_data(json.loads(idaslicer.format_user_data(before)))
    assert problems == []
    assert done["name"] == len(before["names"])
    assert done["local type"] == 1
    assert idaslicer.export_user_data() == before
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
ida_bytes.set_cmt({callee}, "from the slice", False)
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
    assert ida_bytes.get_cmt(callee, False) == "from the slice"
    assert "SliceS" in idaslicer._applied_type(via)
    assert "slice_var" in _lvar_names(fill)

    after = _json(idaslicer.export_user_data())
    before = _json(before)
    for key in ("patches", "functions", "extra_comments", "func_comments", "operands", "bookmarks"):
        assert after[key] == before[key], key
    names = lambda d: {tuple(n) for n in d["names"]}
    assert names(after) - names(before) == {(callee, "slice_callee", False)}
    assert names(before) - names(after) == {(callee, "callee_a", False)}
    assert [c for c in after["comments"] if c not in before["comments"]] == [[callee, False, "from the slice"]]
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
    moved = {k: (v[0] + delta, v[1]) if isinstance(v, tuple) else v if isinstance(v, bytes) else v + delta for k, v in edits.items()}
    _wipe(moved)
    assert idaslicer.shift_by_image_base(before) is True
    _, problems = idaslicer.import_user_data(before)
    assert problems == []
    assert ida_name.get_ea_name(moved["leaf"], 0) == "my_leaf"
    assert ida_bytes.get_bytes(moved["g_msg"], 5) == b"HELLO"
    assert ida_bytes.get_cmt(moved["root"], True) == "repeatable"
    assert ida_bytes.is_enum(ida_bytes.get_flags(moved["enum"][0]), moved["enum"][1])
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
