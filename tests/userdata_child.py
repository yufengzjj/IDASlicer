"""User-data export/import on a second database, in a process of its own:
idalib holds one database per process, and the tests' own is already open.
`run()` runs this file as

    python userdata_child.py <binary or .i64> <out.json> [--script edits.py] [--import export.json]

which opens and analyses the file, runs the script (with `idaslicer` in its
globals), imports the export, and writes {"problems", "export"} to out.json."""

import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def run(path, out, script=None, import_path=None) -> dict:
    argv = [sys.executable, __file__, str(path), str(out)]
    if script:
        argv += ["--script", str(script)]
    if import_path:
        argv += ["--import", str(import_path)]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=300, check=False)
    if r.returncode != 0:
        raise AssertionError(f"userdata_child exited with {r.returncode:#x}:\n{r.stdout}\n{r.stderr}")
    with open(out, encoding="utf-8") as f:
        return json.load(f)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("path")
    p.add_argument("out")
    p.add_argument("--script")
    p.add_argument("--import", dest="import_path")
    args = p.parse_args()

    # As in conftest: no user plugins in the analysis, and a Qt stand-in.
    os.environ["IDAUSR"] = tempfile.mkdtemp(prefix="idaslicer-idausr-")
    import idapro

    sys.path[:0] = [HERE, os.path.dirname(HERE)]
    import qt_stub

    qt_stub.install({})

    if idapro.open_database(args.path, True) != 0:
        sys.exit(f"cannot open {args.path}")
    import ida_auto

    import idaslicer

    ida_auto.auto_wait()
    if args.script:
        with open(args.script, encoding="utf-8") as f:
            exec(compile(f.read(), args.script, "exec"), {"idaslicer": idaslicer})  # noqa: S102 -- the test's own edit script
        ida_auto.auto_wait()
    problems = []
    if args.import_path:
        _, problems = idaslicer.import_user_data(idaslicer.load_user_data(args.import_path))
    result = {"problems": problems, "export": idaslicer.export_user_data()}
    idapro.close_database(False)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f)


if __name__ == "__main__":
    main()
