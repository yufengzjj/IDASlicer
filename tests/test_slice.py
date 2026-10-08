import os
import pickle
import shutil
import subprocess
import sys

import ida_bytes
import ida_ida
import ida_segment
import ida_typeinf
import pytest
from inspect_idb import inspect

import idaslicer

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(os.path.dirname(HERE), "obj_minis", "elf_arm64.i64")


def values(start, end):
    return [ida_bytes.get_byte(a) if ida_bytes.is_loaded(a) else None for a in range(start, end)]


@pytest.fixture
def worker_runs(monkeypatch):
    """Runs the worker for real, exactly as perform_slice asked: the interpreter
    it picked under this venv's sys.prefix, the scrubbed env, the pickle, the script."""
    calls = []
    real_run = subprocess.run

    def run(argv, **kw):
        calls.append((argv, kw))
        kw.pop("creationflags", None)
        return real_run(argv, **kw)

    monkeypatch.setattr(idaslicer.subprocess, "run", run)
    return calls


def test_detect_file_type(db, plugin):
    assert plugin.detect_file_type() == "elf_arm64"


def test_perform_slice(db, plugin, qt, worker_runs):
    origins = {}
    plugin._add_collected_ranges(idaslicer.collect_recursive_ranges(db.ea("root"), origins), origins)
    entries = plugin.entries
    plugin.perform_slice(entries, plugin.detect_file_type())

    assert qt.box.calls[-1][:2] == ("information", "Success"), qt.box.calls
    ((argv, kw),) = worker_runs
    assert os.path.samefile(argv[0], sys.executable)
    assert not [k for k in kw["env"] if k != "IDADIR" and ("IDA" in k.upper() or k in ("PYTHONPATH", "PYTHONHOME"))]
    assert not os.path.exists(argv[1]) and not os.path.exists(argv[2]), "temp files left behind"

    out = inspect(db.path.with_name("scan_arm64_slice.i64"), [(e.start, e.end) for e in entries])
    segs = {(s["start"], s["end"]): s for s in out["segments"]}
    for e, got in zip(entries, out["ranges"]):
        seg = segs[(e.start, e.end)]
        assert (seg["perm"], seg["type"], seg["class"], seg["align"]) == (e.perm, e.seg_type, idaslicer.get_seg_class(e.seg_type), e.align), e.name
        assert seg["bitness"] == ida_segment.getseg(e.start).bitness, e.name
        assert got == values(e.start, e.end), e.name
    bss = next(got for e, got in zip(entries, out["ranges"]) if e.seg_type == ida_segment.SEG_BSS)
    assert set(bss) == {None}
    for name in ["root", "leaf", "via_ptr2", "g_table", "g_n2", "g_bss", "g_msg"]:
        assert out["names"].get(name) == db.ea(name), name


@pytest.mark.parametrize(
    "returncode, stdout, box",
    [
        (0, "Successfully processed segments.\n", ("information", "Success")),
        (2, f"{idaslicer.WORKER_PROBLEM}a: could not add segment\n", ("warning", "Slice incomplete")),
        (1, "Traceback ...\n", ("critical", "Error")),
    ],
)
def test_perform_slice_reports_worker_result(db, plugin, qt, monkeypatch, returncode, stdout, box):
    monkeypatch.setattr(idaslicer.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, returncode, stdout, ""))
    leaf = db.ea("leaf")
    plugin.perform_slice([idaslicer.SlicerEntry("a", leaf, leaf + 4, 5, ida_segment.SEG_CODE, 0)], "elf_arm64")
    assert qt.box.calls[-1][:2] == box
    if returncode == 2:
        assert "a: could not add segment" in qt.box.calls[-1][2]


def test_perform_slice_without_template(db, plugin, qt, worker_runs):
    leaf = db.ea("leaf")
    plugin.perform_slice([idaslicer.SlicerEntry("a", leaf, leaf + 4, 5, ida_segment.SEG_CODE, 0)], "pe_x86")
    assert qt.box.calls[-1][:2] == ("warning", "Error")
    assert "Template not found" in qt.box.calls[-1][2]
    assert not worker_runs


def test_perform_slice_sends_the_compiler(db, plugin, qt, monkeypatch):
    sent = []

    def run(argv, **kw):
        with open(argv[2], "rb") as f:
            sent.append(pickle.load(f))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(idaslicer.subprocess, "run", run)
    leaf = db.ea("leaf")
    plugin.perform_slice([idaslicer.SlicerEntry("a", leaf, leaf + 4, 5, ida_segment.SEG_CODE, 0)], "elf_arm64")
    ((_, cc_id, _),) = sent
    assert cc_id == ida_ida.inf_get_cc_id()


@pytest.mark.parametrize("template", sorted(f.removesuffix(".i64") for f in os.listdir(os.path.dirname(TEMPLATE)) if f.endswith(".i64")))
def test_template_matches_its_name(template, tmp_path):
    """perform_slice picks the template by detect_file_type()'s name, so each
    must hold that file type and processor, and nothing at the addresses a slice uses."""
    path = tmp_path / f"{template}.i64"
    shutil.copy(os.path.join(os.path.dirname(TEMPLATE), path.name), path)
    res = inspect(path)
    ftype = {ida_ida.f_ELF: "elf", ida_ida.f_PE: "pe", ida_ida.f_MACHO: "macho"}[res["filetype"]]
    proc = {"metapc": ("x86", "x64"), "arm": ("arm32", "arm64")}[res["procname"].lower()][res["is_64"]]
    assert f"{ftype}_{proc}" == template
    assert all(s["end"] <= 1 for s in res["segments"]), res["segments"]
    assert res["names"] == {}
    if ftype == "pe":
        assert res["cc_id"] == ida_typeinf.COMP_MS


def _run_worker(tmp_path, out, entries_data, cc_id=None):
    data = tmp_path / "data.pickle"
    data.write_bytes(pickle.dumps((str(out), cc_id, entries_data)))
    script = tmp_path / "worker.py"
    script.write_text(idaslicer.WORKER_SCRIPT)
    return subprocess.run([sys.executable, str(script), str(data)], capture_output=True, text=True, timeout=300, check=False)


def test_worker_keeps_going_past_a_bad_range(tmp_path):
    out = tmp_path / "slice.i64"
    shutil.copy(TEMPLATE, out)
    good = {
        "name": "good",
        "start": 0x100000,
        "end": 0x100010,
        "perm": 5,
        "seg_type": ida_segment.SEG_CODE,
        "align": ida_segment.saRelDble,
        "seg_class": "CODE",
        "names": [[4, "good_mid"]],
        "content": bytes(range(16)),
        "inited": [(0, 4), (8, 8)],
    }
    empty = dict(good, name="empty", start=0x200000, end=0x200000, names=[], content=b"", inited=[])
    r = _run_worker(tmp_path, out, [empty, good])
    assert r.returncode == idaslicer.WORKER_EXIT_PROBLEMS, r.stdout + r.stderr
    problems = [line for line in r.stdout.splitlines() if line.startswith(idaslicer.WORKER_PROBLEM)]
    assert len(problems) == 1 and problems[0].startswith(f"{idaslicer.WORKER_PROBLEM}empty:")

    res = inspect(out, [(0x100000, 0x100010)])
    assert res["ranges"] == [[0, 1, 2, 3, None, None, None, None, *range(8, 16)]]
    seg = next(s for s in res["segments"] if s["start"] == 0x100000)
    assert (seg["name"], seg["end"], seg["perm"], seg["class"]) == ("good", 0x100010, 5, "CODE")
    assert res["names"]["good_mid"] == 0x100004


def test_worker_takes_the_source_compiler(tmp_path):
    """An MSVC name in a GNU template only demangles once the compiler is set."""
    out = tmp_path / "slice.i64"
    shutil.copy(TEMPLATE, out)
    entry = {
        "name": "??0bad_array_new_length@std@@QEAA@XZ_0x100000",
        "start": 0x100000,
        "end": 0x100010,
        "perm": 5,
        "seg_type": ida_segment.SEG_CODE,
        "align": ida_segment.saRelDble,
        "seg_class": "CODE",
        "names": [[0, "??0bad_array_new_length@std@@QEAA@XZ"], [8, "_ZNSt20bad_array_new_lengthC2Ev"]],
        "content": bytes(16),
    }
    r = _run_worker(tmp_path, out, [entry], ida_typeinf.COMP_MS)
    assert r.returncode == 0, r.stdout + r.stderr

    res = inspect(out)
    assert res["cc_id"] == ida_typeinf.COMP_MS
    assert res["shown_names"]["??0bad_array_new_length@std@@QEAA@XZ"] == "std::bad_array_new_length::bad_array_new_length(void)"
    assert res["shown_names"]["_ZNSt20bad_array_new_lengthC2Ev"] == "std::bad_array_new_length::bad_array_new_length(void)"


def test_worker_keeps_64bit_code_in_pe_x64(tmp_path):
    """On x86, add_segm makes a 32-bit segment even in a 64-bit database."""
    out = tmp_path / "slice.i64"
    shutil.copy(os.path.join(os.path.dirname(TEMPLATE), "pe_x64.i64"), out)
    entry = {
        "name": "code",
        "start": 0x140001000,
        "end": 0x140001010,
        "perm": 5,
        "seg_type": ida_segment.SEG_CODE,
        "align": ida_segment.saRelPara,
        "bitness": 2,
        "seg_class": "CODE",
        "content": b"\x90" * 16,
    }
    r = _run_worker(tmp_path, out, [entry])
    assert r.returncode == 0, r.stdout + r.stderr
    seg = next(s for s in inspect(out)["segments"] if s["start"] == 0x140001000)
    assert seg["bitness"] == 2


def test_worker_hard_failure(tmp_path):
    r = _run_worker(tmp_path, tmp_path / "missing" / "slice.i64", [])
    assert r.returncode == 1
