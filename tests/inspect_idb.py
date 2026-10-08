"""What a database holds, read in a separate process: idalib holds one database
per process, and the tests' own is already open. `inspect()` runs this file as

    python inspect_idb.py <db.i64> '<json list of [start, end]>'

which prints one `RESULT {json}` line. For each range, every byte is its value,
or null when the byte has none."""

import json
import subprocess
import sys

import idapro


def inspect(path, ranges=()) -> dict:
    argv = [sys.executable, __file__, str(path), json.dumps(list(ranges))]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=300, check=False)
    for line in r.stdout.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line.removeprefix("RESULT "))
    raise AssertionError(f"inspect_idb exited with {r.returncode:#x}:\n{r.stdout}\n{r.stderr}")


def main(path, ranges):
    if idapro.open_database(path, False) != 0:
        sys.exit(f"cannot open {path}")
    import ida_bytes
    import ida_segment
    import idautils

    out = {"segments": [], "ranges": [], "names": {}}
    for ea in idautils.Segments():
        s = ida_segment.getseg(ea)
        out["segments"].append(
            {
                "name": ida_segment.get_segm_name(s),
                "start": s.start_ea,
                "end": s.end_ea,
                "perm": s.perm,
                "type": s.type,
                "class": ida_segment.get_segm_class(s),
                "align": s.align,
            }
        )
    for s, e in ranges:
        out["ranges"].append([ida_bytes.get_byte(a) if ida_bytes.is_loaded(a) else None for a in range(s, e)])
    out["names"] = {name: ea for ea, name in idautils.Names()}
    idapro.close_database(False)
    print("RESULT " + json.dumps(out))


if __name__ == "__main__":
    main(sys.argv[1], json.loads(sys.argv[2]) if len(sys.argv) > 2 else [])
