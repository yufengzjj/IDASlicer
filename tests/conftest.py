"""Runs idaslicer.py under idalib (headless IDA). Every test module gets its own
freshly analysed copy of the arm64 sample, because idalib holds one database
per process and some tests change theirs."""

import bisect
import enum
import glob
import os
import shutil
import subprocess
import sys
import tempfile
import types
from typing import ClassVar

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "tests", "samples")

# An empty user directory keeps the user's own plugins (and this one, as a
# plugin) out of the analysis. The license lives in IDADIR, not here.
os.environ["IDAUSR"] = tempfile.mkdtemp(prefix="idaslicer-idausr-")

# Must come before any ida_* import.
import idapro
import qt_stub


class _StandardButton(enum.Flag):
    Yes = enum.auto()
    No = enum.auto()


class FakeMessageBox:
    """Stands in for QMessageBox. Static calls are recorded in `calls`; the
    answers to question() and to the overwrite dialog come from `answers`,
    by button name."""

    StandardButton = _StandardButton
    calls: ClassVar[list] = []
    answers: ClassVar[dict] = {}

    def __init__(self):
        self._checked = False

    @classmethod
    def reset(cls):
        cls.calls = []
        cls.answers = {}

    @classmethod
    def _record(cls, kind, title, text):
        cls.calls.append((kind, title, text))

    @classmethod
    def information(cls, parent, title, text, *a):
        cls._record("information", title, text)

    @classmethod
    def warning(cls, parent, title, text, *a):
        cls._record("warning", title, text)

    @classmethod
    def critical(cls, parent, title, text, *a):
        cls._record("critical", title, text)

    @classmethod
    def question(cls, parent, title, text, *a):
        cls._record("question", title, text)
        return _StandardButton[cls.answers.get("question", "Yes")]

    # The overwrite-conflict dialog is built as an instance.
    def setWindowTitle(self, t):
        self._title = t

    def setText(self, t):
        self._text = t

    def setStandardButtons(self, b):
        pass

    def setDefaultButton(self, b):
        pass

    def setCheckBox(self, cb):
        cb._checked = FakeMessageBox.answers.get("apply_to_all", False)

    def exec(self):
        FakeMessageBox._record("overwrite", self._title, self._text)
        return _StandardButton[FakeMessageBox.answers.get("overwrite", "No")]


class FakeCheckBox:
    def __init__(self, *a):
        self._checked = False

    def isChecked(self):
        return self._checked


class FakeFileDialog:
    files: ClassVar[list] = []

    @classmethod
    def getOpenFileNames(cls, *a):
        return list(cls.files), ""

    @classmethod
    def getOpenFileName(cls, *a):
        return (cls.files[0] if cls.files else ""), ""

    @classmethod
    def getSaveFileName(cls, *a):
        return cls.getOpenFileName()


qt_stub.install({"QMessageBox": FakeMessageBox, "QCheckBox": FakeCheckBox, "QFileDialog": FakeFileDialog})
sys.path.insert(0, ROOT)

import idaslicer


def _find_linker():
    """An ELF lld: $IDASLICER_LD, ld.lld on PATH, or the one rustup ships."""
    if os.environ.get("IDASLICER_LD"):
        return os.environ["IDASLICER_LD"]
    found = shutil.which("ld.lld")
    if found:
        return found
    pattern = os.path.join(os.path.expanduser("~"), ".rustup", "toolchains", "*", "lib", "rustlib", "*", "bin", "gcc-ld", "ld.lld*")
    hits = [h for h in glob.glob(pattern) if not h.endswith(".pdb")]
    return hits[0] if hits else None


@pytest.fixture(scope="session")
def sample_elf(tmp_path_factory):
    clang = shutil.which("clang")
    ld = _find_linker()
    if not clang or not ld:
        pytest.skip("needs clang and an ELF lld (set IDASLICER_LD) to build the arm64 sample")
    out = tmp_path_factory.mktemp("build") / "scan_arm64.elf"
    cmd = [
        clang,
        "--target=aarch64-linux-gnu",
        "-O1",
        "-nostdlib",
        "-static",
        f"-fuse-ld={ld}",
        os.path.join(SAMPLES, "scan_arm64.c"),
        "-o",
        str(out),
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    return out


@pytest.fixture(scope="session")
def stripped_elf(sample_elf):
    """The sample without symbols, and {name: address} read from the original."""
    objcopy, nm = shutil.which("llvm-objcopy"), shutil.which("llvm-nm")
    if not objcopy or not nm:
        pytest.skip("needs llvm-objcopy and llvm-nm for the stripped sample")
    out = sample_elf.with_name("scan_arm64_stripped.elf")
    subprocess.run([objcopy, "--strip-all", str(sample_elf), str(out)], check=True, capture_output=True)
    listing = subprocess.run([nm, "--defined-only", str(sample_elf)], check=True, capture_output=True, text=True).stdout
    symbols = {}
    for line in listing.splitlines():
        addr, _, name = line.split()
        if not name.startswith("$"):  # aarch64 mapping symbols
            symbols[name] = int(addr, 16)
    return out, symbols


class Sample:
    """The open database, with addresses looked up by symbol name: IDA's names,
    or `symbols` for a database built from a stripped binary."""

    def __init__(self, path, symbols=None):
        import idautils

        self.path = path
        self._symbols = symbols
        self._names = sorted((a, n) for n, a in symbols.items()) if symbols else sorted(idautils.Names())
        self._addrs = [a for a, _ in self._names]

    def ea(self, name: str) -> int:
        import ida_name

        if self._symbols is not None:
            return self._symbols[name]
        ea = ida_name.get_name_ea(idaslicer.idaapi.BADADDR, name)
        assert ea != idaslicer.idaapi.BADADDR, f"symbol {name} not found"
        return ea

    def label(self, ea: int) -> str:
        """`sym` or `sym+0xN` from the nearest name at or below `ea`, so results
        read the same whatever addresses the linker picked."""
        i = bisect.bisect_right(self._addrs, ea) - 1
        if i < 0:
            return hex(ea)
        base, name = self._names[i]
        return name if ea == base else f"{name}+{ea - base:#x}"

    def labels(self, ranges) -> list:
        return [f"{self.label(s)}..{self.label(e)}" for s, e in sorted(ranges)]

    def covered(self, ranges, names) -> set:
        """Which of `names` start inside one of `ranges`."""
        return {n for n in names if any(s <= self.ea(n) < e for s, e in ranges)}


def _open_copy(tmp_path_factory, binary, symbols=None):
    """IDA writes its database next to the input, hence the copy."""
    work = tmp_path_factory.mktemp("db") / binary.name
    shutil.copy(binary, work)
    assert idapro.open_database(str(work), True) == 0
    try:
        yield Sample(work, symbols)
    finally:
        idapro.close_database(False)


@pytest.fixture(scope="module")
def db(sample_elf, tmp_path_factory):
    """A freshly analysed copy of the sample, open for the whole module."""
    yield from _open_copy(tmp_path_factory, sample_elf)


@pytest.fixture(scope="module")
def stripped_db(stripped_elf, tmp_path_factory):
    """Like `db`, for the stripped sample. A module uses one or the other."""
    binary, symbols = stripped_elf
    yield from _open_copy(tmp_path_factory, binary, symbols)


@pytest.fixture
def qt():
    FakeMessageBox.reset()
    FakeFileDialog.files = []
    yield types.SimpleNamespace(box=FakeMessageBox, files=FakeFileDialog)
    FakeMessageBox.reset()


@pytest.fixture
def plugin(tmp_path, monkeypatch, qt):
    """A plugin instance without init(): no actions, no UI hooks, and a config
    file and slicer list in tmp_path -- the real config next to the plugin is user data."""
    monkeypatch.setattr(idaslicer.IDASlicerPlugin, "_get_config_path", lambda self: str(tmp_path / "idaslicer_config.json"))
    monkeypatch.setattr(idaslicer.IDASlicerPlugin, "_list_path", lambda self: str(tmp_path / "db.slicer.json"))
    p = idaslicer.IDASlicerPlugin()
    p.form = None
    p.entries = []
    p.last_import_path = ""
    return p


def pytest_addoption(parser):
    parser.addoption("--update-golden", action="store_true", help="rewrite tests/golden/*.json from the current scanner")
