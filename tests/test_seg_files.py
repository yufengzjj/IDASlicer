import hashlib
import pickle
import shutil

import ida_bytes
import ida_domain
import ida_loader
import ida_name
import ida_segment
import pytest
from inspect_idb import inspect

import idaslicer


def _entry(plugin, start, end):
    seg = ida_segment.getseg(start)
    return idaslicer.SlicerEntry(plugin._range_name(start, seg), start, end, seg.perm, seg.type, seg.align)


def _load(path):
    with open(path, "rb") as f:
        return idaslicer._SegUnpickler(f).load()


def _write(path, obj):
    path.write_bytes(pickle.dumps(obj))
    return str(path)


def _values(start, end):
    return [ida_bytes.get_byte(a) if ida_bytes.is_loaded(a) else None for a in range(start, end)]


def _summary(qt):
    kind, title, text = qt.box.calls[-1]
    assert (kind, title) == ("information", "Import Summary")
    return text


@pytest.fixture
def importer(plugin, qt, monkeypatch):
    """`Database.open()` with no path binds to the open database, but in idalib
    leaving the `with` also closes it, unsaved. Inside IDA close() does nothing."""
    monkeypatch.setattr(ida_domain.Database, "close", lambda self, save=None: None)

    def run(*files, **answers):
        qt.box.reset()
        qt.box.answers = answers
        qt.files.files = [str(f) for f in files]
        plugin.import_segments_from_files()
        return _summary(qt)

    return run


def test_save_single_files(db, plugin, qt):
    leaf, callee, bss = db.ea("leaf"), db.ea("callee_a"), db.ea("g_bss")
    plugin.save_segments_to_files([_entry(plugin, leaf, callee), _entry(plugin, bss, bss + 0x20)])
    assert qt.box.calls[-1][:2] == ("information", "Success")

    code = _load(db.path.parent / f"leaf_{leaf:#x}_{leaf:#x}_{callee:#x}.seg")
    assert code["version"] == idaslicer.SEG_FILE_VERSION
    assert (code["start"], code["end"], code["seg_class"]) == (leaf, callee, "CODE")
    assert code["content"] == ida_bytes.get_bytes(leaf, callee - leaf)
    assert code["sig"] == hashlib.md5(code["content"]).hexdigest()
    assert code["inited"] == [(0, callee - leaf)]
    assert code["names"] == [[0, "leaf"]]

    data = _load(db.path.parent / f".bss_{bss:#x}_{bss:#x}_{bss + 0x20:#x}.seg")
    assert (data["seg_class"], data["content"], data["inited"]) == ("BSS", b"", [])


def test_save_merged_file(db, plugin, qt):
    leaf, callee, via = db.ea("leaf"), db.ea("callee_a"), db.ea("via_ptr")
    plugin.save_segments_to_files([_entry(plugin, leaf, callee), _entry(plugin, callee, via)], merge=True)
    merged = _load(db.path.parent / "scan_arm64_merged.seg")
    assert merged["merged"] is True
    assert [(p["start"], p["end"]) for p in merged["entries"]] == [(leaf, callee), (callee, via)]


def test_import_into_free_space(db, plugin, qt, importer, tmp_path):
    leaf, callee = db.ea("leaf"), db.ea("callee_a")
    plugin.save_segments_to_files([_entry(plugin, leaf, callee)])
    payload = _load(db.path.parent / f"leaf_{leaf:#x}_{leaf:#x}_{callee:#x}.seg")
    to = 0x400000
    payload.update(start=to, end=to + (callee - leaf), name=f"moved_{to:#x}", names=[[0, "moved_leaf"]])

    text = importer(_write(tmp_path / "moved.seg", payload))
    assert "Payloads: 1 taken" in text
    seg = ida_segment.getseg(to)
    assert (seg.start_ea, seg.end_ea, ida_segment.get_segm_name(seg)) == (to, to + callee - leaf, f"moved_{to:#x}")
    assert (seg.perm, seg.type) == (payload["perm"], payload["seg_type"])
    assert ida_bytes.get_bytes(to, callee - leaf) == payload["content"]
    assert ida_name.get_name(to) == "moved_leaf"
    assert [(e.name, e.start, e.end) for e in plugin.entries] == [(f"moved_{to:#x}", to, to + callee - leaf)]


def test_import_split_around_existing_segment(db, plugin, importer, tmp_path, qt):
    data = ida_segment.getseg(db.ea("g_counter")).start_ea
    start, end = data - 0x10, data + 8
    payload = {"name": f"x_{start:#x}", "start": start, "end": end, "perm": 6, "seg_class": "DATA", "content": b"\xaa" * (end - start)}

    text = importer(_write(tmp_path / "split.seg", payload), overwrite="Yes")
    assert [c[0] for c in qt.box.calls].count("overwrite") == 1
    assert f"Created segment 'x_{start:#x}' at {start:#x}-{data:#x}" in text
    assert "Overwrote part of '.data'" in text
    assert ida_segment.getseg(start).end_ea == data
    assert _values(start, end) == [0xAA] * (end - start)
    assert [(e.start, e.end) for e in plugin.entries] == [(start, end)]


def test_import_declined_overwrite(db, plugin, importer, tmp_path):
    table = db.ea("g_table")
    before = _values(table, table + 8)
    payload = {"name": "t", "start": table, "end": table + 8, "perm": 6, "seg_class": "DATA", "content": b"\x55" * 8, "names": [[0, "stamped"]]}

    text = importer(_write(tmp_path / "t.seg", payload), overwrite="No")
    assert "1 declined" in text
    assert _values(table, table + 8) == before
    assert ida_name.get_name(table) == "g_table"
    assert plugin.entries == []


def test_import_without_bytes(db, plugin, importer, tmp_path):
    payload = {"start": 0x500000, "end": 0x500100, "perm": 6, "seg_class": "DATA"}
    text = importer(_write(tmp_path / "decl.seg", payload))
    assert "(no bytes)" in text and "1 taken" in text
    assert ida_segment.getseg(0x500000).end_ea == 0x500100
    assert set(_values(0x500000, 0x500100)) == {None}
    assert [(e.name, e.start) for e in plugin.entries] == [(f"imported_{0x500000:#x}", 0x500000)]


@pytest.fixture
def bss_payload(db, plugin):
    """The .seg the plugin writes for g_bss: a range without bytes."""
    start, end = db.ea("g_bss"), db.ea("g_split")
    plugin.save_segments_to_files([_entry(plugin, start, end)])
    payload = _load(db.path.parent / f".bss_{start:#x}_{start:#x}_{end:#x}.seg")
    assert (payload["content"], payload["inited"], payload["seg_type"]) == (b"", [], ida_segment.SEG_BSS)
    return payload


def test_import_bss_into_free_space(db, plugin, importer, tmp_path, bss_payload):
    size = bss_payload["end"] - bss_payload["start"]
    to = 0x900000
    bss_payload.update(start=to, end=to + size, name=f"moved_bss_{to:#x}", names=[[0, "moved_g_bss"]])

    text = importer(_write(tmp_path / "bss.seg", bss_payload))
    assert "1 taken" in text and "(no bytes)" in text
    seg = ida_segment.getseg(to)
    assert (seg.start_ea, seg.end_ea) == (to, to + size)
    assert (seg.perm, seg.type, ida_segment.get_segm_class(seg)) == (bss_payload["perm"], ida_segment.SEG_BSS, "BSS")
    assert seg.align == bss_payload["align"]
    assert set(_values(to, to + size)) == {None}
    assert ida_name.get_name(to) == "moved_g_bss"
    assert [(e.start, e.end, e.seg_type) for e in plugin.entries] == [(to, to + size, ida_segment.SEG_BSS)]


def test_import_bss_over_existing_bss(db, plugin, importer, tmp_path, qt, bss_payload):
    start, end = bss_payload["start"], bss_payload["end"]
    before = ida_segment.getseg(start)
    before = (before.start_ea, before.end_ea, before.type)

    text = importer(_write(tmp_path / "bss.seg", bss_payload))
    assert "overwrite" not in [c[0] for c in qt.box.calls]
    assert "Created segment" not in text and "1 taken" in text
    seg = ida_segment.getseg(start)
    assert (seg.start_ea, seg.end_ea, seg.type) == before
    assert set(_values(start, end)) == {None}
    assert [(e.start, e.end) for e in plugin.entries] == [(start, end)]


def test_import_survives_save(db, plugin, importer, tmp_path, bss_payload):
    """Segment attributes reach the database only through update(); checking
    them in this session would not show a missing one."""
    leaf, callee = db.ea("leaf"), db.ea("callee_a")
    plugin.save_segments_to_files([_entry(plugin, leaf, callee)])
    code = _load(db.path.parent / f"leaf_{leaf:#x}_{leaf:#x}_{callee:#x}.seg")
    payloads = []
    for p, to, label in [(code, 0xA00000, "saved_leaf"), (bss_payload, 0xB00000, "saved_g_bss")]:
        p.update(start=to, end=to + p["end"] - p["start"], name=f"{label}_{to:#x}", names=[[0, label]])
        payloads.append(p)
    importer(*(_write(tmp_path / f"{p['name']}.seg", p) for p in payloads))

    idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    assert ida_loader.save_database(idb, 0)
    saved = tmp_path / "saved.i64"
    shutil.copy(idb, saved)
    out = inspect(saved, [(p["start"], p["end"]) for p in payloads])

    segs = {s["start"]: s for s in out["segments"]}
    for p, got in zip(payloads, out["ranges"], strict=True):
        seg = segs[p["start"]]
        assert (seg["end"], seg["perm"], seg["type"], seg["class"], seg["align"]) == (p["end"], p["perm"], p["seg_type"], p["seg_class"], p["align"])
        assert got == ([*p["content"]] if p["content"] else [None] * (p["end"] - p["start"]))
        assert out["names"][p["names"][0][1]] == p["start"]


def test_import_writes_only_inited_runs(db, importer, tmp_path):
    content = bytes(range(1, 17))
    payload = {"start": 0x600000, "end": 0x600010, "perm": 6, "seg_class": "DATA", "content": content, "inited": [(0, 4), (8, 4)]}
    importer(_write(tmp_path / "runs.seg", payload))
    assert _values(0x600000, 0x600010) == [1, 2, 3, 4, None, None, None, None, 9, 10, 11, 12, None, None, None, None]


@pytest.mark.parametrize("skip, created", [("Yes", False), ("No", True)])
def test_import_md5_mismatch(db, importer, tmp_path, skip, created):
    start = 0x700000 if skip == "Yes" else 0x700100
    payload = {"start": start, "end": start + 4, "perm": 6, "seg_class": "DATA", "content": b"abcd", "sig": "0" * 32}
    text = importer(_write(tmp_path / f"md5{skip}.seg", payload), question=skip)
    assert ("1 skipped on MD5" in text) is not created
    assert (ida_segment.getseg(start) is not None) is created


def test_import_bad_files(db, plugin, importer, tmp_path):
    marker = tmp_path / "pwned"
    evil = tmp_path / "evil.seg"
    evil.write_bytes(b"cos\nmkdir\n(V" + str(marker).encode() + b"\ntR.")
    invalid = _write(tmp_path / "invalid.seg", {"start": 0x710000, "end": 0x710004, "content": b"abcd"})
    bad_runs = _write(tmp_path / "runs.seg", {"start": 0x710000, "end": 0x710004, "perm": 6, "seg_class": "DATA", "inited": [("x",)]})

    text = importer(str(evil), invalid, bad_runs)
    assert not marker.exists()
    assert "Read 2 payload(s) from 3 file(s), 1 unreadable." in text
    assert "2 invalid" in text
    assert ida_segment.getseg(0x710000) is None
    assert plugin.entries == []


def test_import_merged_file(db, plugin, importer, tmp_path):
    parts = [
        {"name": f"m_{s:#x}", "start": s, "end": s + 0x10, "perm": 6, "seg_class": "DATA", "content": bytes([s >> 4 & 0xFF]) * 0x10}
        for s in (0x800000, 0x800010)
    ]
    text = importer(_write(tmp_path / "merged.seg", {"version": 1, "merged": True, "entries": parts}))
    assert "Read 2 payload(s) from 1 file(s)" in text
    assert [ida_segment.get_segm_name(ida_segment.getseg(p["start"])) for p in parts] == ["m_0x800000", "m_0x800010"]
    # The second range starts a segment of its own, so the rows stay apart.
    assert [(e.start, e.end) for e in plugin.entries] == [(0x800000, 0x800010), (0x800010, 0x800020)]

    # Importing the same file again lists nothing new.
    importer(_write(tmp_path / "merged.seg", {"version": 1, "merged": True, "entries": parts}), overwrite="Yes")
    assert len(plugin.entries) == 2
