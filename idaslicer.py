import hashlib
import json
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable

import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_nalt
import ida_name
import ida_range
import ida_segment
import ida_ua
import ida_xref
import idaapi
import idautils
from PySide6 import QtCore, QtWidgets

try:
    import ida_domain
except ImportError:
    ida_domain = None  # ty:ignore[invalid-assignment]

WORKER_SCRIPT = """
import sys
import pickle
import os
import traceback

def run_worker(data_path):
    try:
        import ida_domain
        import ida_segment
        import ida_name
    except ImportError:
        print(traceback.format_exc())
        sys.exit(1)

    try:
        with open(data_path, 'rb') as f:
            out_path, entries_data = pickle.load(f)

        with ida_domain.Database.open(out_path) as db:
            name_counts = {}
            for entry_data in entries_data:
                name = entry_data['name']
                if name in name_counts:
                    name_counts[name] += 1
                    unique_name = f"{name}{name_counts[name]}"
                else:
                    name_counts[name] = 0
                    unique_name = name

                seg = db.segments.add(
                    0, entry_data['start'], entry_data['end'], unique_name, entry_data['seg_class']
                )
                if not seg:
                    print(f"Failed to add segment: {unique_name}")
                    continue
                db.segments.set_permissions(seg, entry_data['perm'])
                seg_type = entry_data.get('seg_type')
                align = entry_data.get('align')
                if seg_type is not None or align is not None:
                    seg_obj = ida_segment.getseg(entry_data['start'])
                    if seg_obj is not None:
                        if seg_type is not None:
                            seg_obj.type = seg_type
                        if align is not None:
                            seg_obj.align = align
                        seg_obj.update()
                if entry_data['content']:
                    db.bytes.set_bytes_at(entry_data['start'], entry_data['content'])
                for off, nm in entry_data.get('names', []):
                    ida_name.set_name(
                        entry_data['start'] + off, nm, ida_name.SN_NOWARN | ida_name.SN_NOCHECK
                    )

            # Database is saved when db.__exit__ is called
            print("Successfully processed segments.")
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    run_worker(sys.argv[1])
"""

# --- Data Model ---


def _merge_intervals(intervals: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge contiguous/overlapping intervals into runs; leave real gaps as-is.
    Accepts any iterable of ``(start, end)`` (list or set) -- it sorts a set() of them.

    This runs *after* a scan finishes, on its results. It is not part of the
    scanner: `processed_ranges` / `_is_range_covered` still own termination, and
    nothing here feeds back into a worklist."""
    intervals = sorted(set(intervals))
    if not intervals:
        return []
    merged = []
    cs, ce = intervals[0]
    for s, e in intervals[1:]:
        if s <= ce:
            ce = max(ce, e)
        else:
            merged.append((cs, ce))
            cs, ce = s, e
    merged.append((cs, ce))
    return merged


def _added_msg(added: int, extended: int) -> str:
    """Report what a scan did to the list. Merging means a discovery can land
    without creating a row -- it stretches an entry instead -- so "added 0" on
    its own would read as "nothing happened"."""
    if added and extended:
        return f"Added {added} ranges and extended {extended} existing ones."
    if extended:
        return f"Extended {extended} existing ranges."
    return f"Added {added} ranges to the slicer list."


def _merge_entries(entries: list) -> list:
    """Collapse entries whose ranges touch or overlap into one entry per run.
    The entry that *starts* a run survives and is stretched to the run's end:
    its name and permissions already describe that start, and `_range_name`
    derives names from the start too, so the naming stays consistent. `sig` is
    recomputed because the range changed."""
    by_start = {}
    for e in entries:
        by_start.setdefault(e.start, e)
    merged = []
    for start, end in _merge_intervals((e.start, e.end) for e in entries):
        head = by_start[start]
        if head.end != end:
            head.end = end
            head.update_sig()
        merged.append(head)
    return merged


class SlicerEntry:
    def __init__(self, name, start, end, perm, seg_type, align, sig="", recursive=False, ref=None):
        self.name = name
        self.start = start
        self.end = end
        self.perm = perm  # rwx
        self.seg_type = seg_type
        self.align = align
        # True if this range was discovered by a recursive reference scan. Such
        # entries are re-scanned when their range is edited.
        self.recursive = recursive
        # Address of the instruction or pointer whose reference pulled this range
        # in, or None when nothing referenced it: a scan seed, a hand-added range,
        # or an entry saved before this field existed. Provenance only, never read
        # by the scanner.
        self.ref = ref
        self.sig = sig
        if not self.sig:
            self.update_sig()

    def update_sig(self):
        size = self.end - self.start
        if size > 0:
            content = ida_bytes.get_bytes(self.start, size)
            if content:
                self.sig = hashlib.md5(content).hexdigest()
            else:
                self.sig = "error"
        else:
            self.sig = ""

    def to_dict(self):
        return {
            "name": self.name,
            "start": self.start,
            "end": self.end,
            "perm": self.perm,
            "seg_type": self.seg_type,
            "align": self.align,
            "sig": self.sig,
            "recursive": self.recursive,
            "ref": self.ref,
        }

    @staticmethod
    def from_dict(d):
        return SlicerEntry(
            d.get("name", ""),
            d.get("start", 0),
            d.get("end", 0),
            d.get("perm", 0),
            d.get("seg_type", 0),
            d.get("align", 0),
            d.get("sig", ""),
            d.get("recursive", False),
            d.get("ref"),
        )

    def size(self):
        return self.end - self.start


def _record_origin(origins: dict, addr: int, ref_from: int | None):
    """Note that `addr` was pulled into the scan by the reference at `ref_from`.

    `origins` maps a discovered start address to the address that referenced it.
    It is provenance only: the scanner never reads it back, so it cannot affect
    which ranges are collected or when the worklists terminate.

    First discovery wins -- an address is usually reachable from several places,
    and the reference that actually pulled it in is the informative one. The None
    guard is not cosmetic: setdefault(addr, None) would plant a key and lock out
    the real referrer found later."""
    if ref_from is None:
        return
    origins.setdefault(addr, ref_from)


def _ref_label(ea: int | None) -> str:
    """Render a referrer address for the Ref column: an address, plus where it
    sits if that can be said more usefully than a bare number."""
    if ea is None:
        return ""
    func = ida_funcs.get_func(ea)
    if func:
        name = ida_funcs.get_func_name(func.start_ea)
        off = ea - func.start_ea
        if name:
            return f"{hex(ea)} ({name}+{hex(off)})" if off else f"{hex(ea)} ({name})"
    name = ida_name.get_name(ea)
    return f"{hex(ea)} ({name})" if name else hex(ea)


def get_seg_class(seg_type):
    if seg_type == ida_segment.SEG_CODE:
        return "CODE"
    elif seg_type == ida_segment.SEG_BSS:
        return "BSS"
    return "DATA"


# Schema version for the pickled .seg payload (a plain dict). Bump when the
# field set changes incompatibly.
SEG_FILE_VERSION = 1


def _truncate_filename_name(name, suffix, max_bytes=255):
    """Truncate only the variable `name` portion so that `name + suffix` fits
    within `max_bytes` (UTF-8), keeping the metadata `suffix` intact so the
    filename remains parseable on import."""
    budget = max_bytes - len(suffix.encode("utf-8"))
    if budget <= 0:
        return ""
    encoded = name.encode("utf-8")
    if len(encoded) <= budget:
        return name
    # 'ignore' drops any trailing incomplete multi-byte sequence
    return encoded[:budget].decode("utf-8", errors="ignore")


# Scanner tuning, edited via the panel's Settings button and persisted globally
# (not under the md5-keyed entries) in idaslicer_config.json.
#
# Module-level rather than plugin attributes because the scanner is a tree of
# free functions that never receives the plugin instance -- threading these
# through collect_recursive_ranges -> _drain_functions -> _scan_worklist ->
# check_* would touch a dozen signatures to deliver two values.
DEFAULT_SETTINGS = {
    "max_explore_len": 128,
    "skip_named_data": False,
}
SETTINGS = dict(DEFAULT_SETTINGS)


def _apply_stored_settings(stored):
    """Copy validated values out of a loaded config into SETTINGS.

    Validated rather than trusted: idaslicer_config.json is hand-editable, and a
    bad type here would not surface until it blew up deep inside a scan. The
    bool check on max_explore_len is not redundant -- bool is an int subclass, so
    a JSON `true` would otherwise sail through as a length."""
    if not isinstance(stored, dict):
        return
    val = stored.get("max_explore_len")
    if isinstance(val, int) and not isinstance(val, bool) and val >= 0:
        SETTINGS["max_explore_len"] = val
    val = stored.get("skip_named_data")
    if isinstance(val, bool):
        SETTINGS["skip_named_data"] = val


def get_loose_data_range(ea, max_explore_len=0):
    end_ea = ea
    seg = ida_segment.getseg(ea)
    if seg and seg.type == ida_segment.SEG_BSS:
        end_ea = ida_bytes.get_item_end(ea)
        return ida_range.range_t(ea, end_ea)
    while True:
        if end_ea == idaapi.BADADDR or not ida_bytes.is_mapped(end_ea):
            break
        if end_ea != ea and ida_name.get_name(end_ea):
            break
        next_ea = ida_bytes.get_item_end(end_ea)
        if next_ea <= end_ea or next_ea == idaapi.BADADDR:
            break
        end_ea = next_ea
        if max_explore_len <= 0 or end_ea - ea >= max_explore_len:
            break
    return ida_range.range_t(ea, end_ea)


def _merge_code_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge per-instruction intervals into contiguous code runs.leave gaps as it is"""
    if not intervals:
        return []
    intervals.sort()
    merged = []
    cs, ce = intervals[0]
    for s, e in intervals[1:]:
        if s <= ce:  # contiguous / overlapping instructions
            ce = max(ce, e)
        else:
            merged.append((cs, ce))
            cs, ce = s, e
    merged.append((cs, ce))
    return merged


def reconstruct_func_range(start_ea) -> list[tuple[int, int]]:
    """Best-effort reconstruction of a function's extent when IDA has NOT
    defined a function at `start_ea` -- e.g. a control-flow-flattened or
    obfuscated routine that has data (jump tables / inline constants) embedded
    between its code blocks, which makes IDA refuse to create a function.

    Floods intra-procedural control flow from `start_ea`: follows fall-through
    and local jump targets, but NOT calls (BL/CALL target other functions) and
    does not cross into a different already-defined function (tail calls).

    Returns a LIST of (start, end) ranges -- the reached code blocks, without
    embedded pure-data gaps bridged."""
    visited = set()
    stack = [start_ea]
    intervals = []

    def _is_other_func_start(ea):
        f = ida_funcs.get_func(ea)
        return f is not None and f.start_ea == ea and f.start_ea != start_ea

    while stack:
        ea = stack.pop()
        if ea == idaapi.BADADDR or ea in visited or not ida_bytes.is_mapped(ea):
            continue
        if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            continue
        insn = ida_ua.insn_t()  # ty:ignore[missing-argument]
        size = ida_ua.decode_insn(insn, ea)
        if size <= 0:
            continue
        visited.add(ea)
        intervals.append((ea, ea + size))

        # Follow jump targets that stay within this procedure. Skip calls and
        # jumps that land on the start of another defined function (tail calls).
        for xref in idautils.XrefsFrom(ea, 0):
            if xref.type in (ida_xref.fl_JN, ida_xref.fl_JF):
                if not _is_other_func_start(xref.to):
                    stack.append(xref.to)

        # Fall through to the next instruction unless this one stops flow
        # (RET, ...). Calls (BL) don't stop flow, so execution continues.
        if not ida_idp.is_ret_insn(insn):
            nxt = ea + size
            if not _is_other_func_start(nxt):
                stack.append(nxt)

    return _merge_code_intervals(intervals)


def check_func_range(
    ranges: list[ida_range.range_t],
    ref: int,
    cur_func: ida_funcs.func_t,
    funcs_to_export: list[int] | None,
    processed_ranges: set[tuple[int, int]],
    origins: dict,
    ref_from: int | None = None,
):
    """check the possible func range(or just a commom code chunk)

    `ref_from` is the address whose reference reached `ref`, recorded as the
    provenance of every range this adds. The reconstructed blocks all inherit it:
    only the block holding `ref` is reached by the reference itself, but the rest
    come in as a consequence of it, which is what the Ref column reports."""
    func = ida_funcs.get_func(ref)
    if func and func.start_ea != cur_func.start_ea:
        if ref == func.start_ea:
            if funcs_to_export is not None:
                funcs_to_export.extend(get_recursive_functions(func.start_ea, origins, ref_from))
        else:
            if func.start_ea <= ref < func.end_ea:
                r = ida_range.range_t(ref, func.end_ea)
                if not _is_range_covered(processed_ranges, ref, func.end_ea):
                    _record_origin(origins, ref, ref_from)
                    ranges.append(r)
            else:
                for s, e in reconstruct_func_range(ref):
                    r = ida_range.range_t(s, e)
                    if not _is_range_covered(processed_ranges, s, e):
                        _record_origin(origins, s, ref_from)
                        ranges.append(r)
    elif not func:
        for s, e in reconstruct_func_range(ref):
            r = ida_range.range_t(s, e)
            if not _is_range_covered(processed_ranges, s, e):
                _record_origin(origins, s, ref_from)
                ranges.append(r)


def check_c_ref_range(
    ranges: list[ida_range.range_t],
    addr: int,
    cur_range: tuple[int, int],
    cur_func: ida_funcs.func_t,
    funcs_to_export: list[int] | None,
    processed_ranges: set[tuple[int, int]],
    origins: dict,
):
    """check code ref at addr"""
    for ref in idautils.XrefsFrom(addr, ida_xref.XREF_FAR):
        if cur_range[0] <= ref.to < cur_range[1]:
            continue
        if ref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
            if funcs_to_export is not None:
                funcs_to_export.extend(get_recursive_functions(ref.to, origins, addr))
            continue
        check_func_range(ranges, ref.to, cur_func, funcs_to_export, processed_ranges, origins, addr)


def get_ref_from_insn(ea):
    insn = ida_ua.insn_t()  # ty:ignore[missing-argument]
    if ida_ua.decode_insn(insn, ea) == 0:
        return None

    mn = insn.get_canon_mnem()
    if mn not in ("ADR", "ADRL", "ADRP", "LDR"):
        return None
    if mn in ("ADRP", "LDR"):
        for xref in idautils.XrefsFrom(ea, ida_xref.XREF_DATA):
            return xref.to
    for op in insn.ops:
        if op.type in (idaapi.o_mem, idaapi.o_imm, idaapi.o_far, idaapi.o_near):
            if op.addr != 0 and op.addr != idaapi.BADADDR:
                return op.addr
            if op.value != 0 and op.value != idaapi.BADADDR:
                return op.value
    return None


def check_o_ref_range(
    ranges: list[ida_range.range_t],
    cur_range: tuple[int, int],
    cur_func: ida_funcs.func_t,
    funcs_to_export: list[int] | None,
    processed_ranges: set[tuple[int, int]],
    origins: dict,
    skip_named_data: bool | None = None,
    max_explore_len: int | None = None,
):
    """check code opraand ref in cur_range"""
    # None means "whatever the panel is set to". Resolved here rather than in the
    # signature because default arguments are bound once at import, which would
    # freeze the setting at its startup value.
    if skip_named_data is None:
        skip_named_data = SETTINGS["skip_named_data"]
    if max_explore_len is None:
        max_explore_len = SETTINGS["max_explore_len"]
    for head in idautils.Heads(*cur_range):
        o_ref = get_ref_from_insn(head)
        if o_ref is None:
            continue
        if cur_range[0] <= o_ref < cur_range[1]:
            continue
        if o_ref == idaapi.BADADDR or not ida_bytes.is_mapped(o_ref):
            continue
        o_flags = ida_bytes.get_flags(o_ref)
        if ida_bytes.is_code(o_flags):
            if funcs_to_export is not None:
                funcs_to_export.extend(get_recursive_functions(o_ref, origins, head))
        elif ida_bytes.is_data(o_flags):
            if skip_named_data and ida_bytes.has_name(o_flags):
                continue
            o_size = ida_bytes.get_item_size(o_ref)
            if o_size <= 1:
                r = get_loose_data_range(o_ref, max_explore_len)
            else:
                r = ida_range.range_t(o_ref, o_ref + o_size)
            if not _is_range_covered(processed_ranges, r.start_ea, r.end_ea):
                _record_origin(origins, r.start_ea, head)
                ranges.append(r)
        else:
            if skip_named_data and ida_bytes.has_name(o_flags):
                continue
            r = get_loose_data_range(o_ref, max_explore_len)
            if not _is_range_covered(processed_ranges, r.start_ea, r.end_ea):
                _record_origin(origins, r.start_ea, head)
                ranges.append(r)


def check_d_ref_range(
    ranges: list[ida_range.range_t],
    cur_range: tuple[int, int],
    cur_func: ida_funcs.func_t,
    funcs_to_export: list[int] | None,
    processed_ranges: set[tuple[int, int]],
    origins: dict,
    skip_named_data: bool | None = None,
    max_explore_len: int | None = None,
):
    """check data ref"""
    if skip_named_data is None:
        skip_named_data = SETTINGS["skip_named_data"]
    if max_explore_len is None:
        max_explore_len = SETTINGS["max_explore_len"]
    ea = cur_range[0]
    ptr_size = ida_ida.inf_get_app_bitness() // 8
    while ea < cur_range[1]:
        next_ea = ida_bytes.get_item_end(ea)
        if next_ea <= ea or next_ea == idaapi.BADADDR:
            break
        if ida_bytes.get_item_size(ea) == ptr_size:
            data = ida_bytes.get_bytes(ea, ptr_size)
            if data is not None and len(data) == ptr_size:
                ptr = int.from_bytes(data, "big" if ida_ida.inf_is_be() else "little")
                if (
                    not (cur_range[0] <= ptr < cur_range[1]) and ptr != 0 and ptr != idaapi.BADADDR and ida_bytes.is_mapped(ptr)
                    # need the name have to include ranges in SEG_XTRN
                    # and ida_segment.segtype(ptr) != ida_segment.SEG_XTRN
                ):
                    flags = ida_bytes.get_flags(ptr)
                    # The referrer is `ea`, the address the pointer was read from,
                    # not the item it points at.
                    if ida_bytes.is_code(flags):
                        if funcs_to_export is not None:
                            funcs_to_export.extend(get_recursive_functions(ptr, origins, ea))
                    elif not (skip_named_data and ida_bytes.has_name(flags)):
                        d_size = ida_bytes.get_item_size(ptr)
                        if d_size <= 1:
                            r = get_loose_data_range(ptr, max_explore_len)
                        else:
                            r = ida_range.range_t(ptr, ptr + d_size)
                        if not _is_range_covered(processed_ranges, r.start_ea, r.end_ea):
                            _record_origin(origins, r.start_ea, ea)
                            ranges.append(r)
        ea = next_ea


def is_stub_func(func) -> bool:
    """A library function or a named import thunk: not exported in full, only
    its first instruction is collected (see `_collect_stub_range`) so that
    references to it resolve to a name instead of an unknown address."""
    if func.flags & ida_funcs.FUNC_LIB:
        return True
    if func.flags & ida_funcs.FUNC_THUNK:
        if ida_bytes.has_name(ida_bytes.get_flags(func.start_ea)):
            return True
    return False


def get_recursive_functions(start_ea, origins: dict, ref_from: int | None = None) -> list[int]:
    """Get all functions reachable from start_ea. Library functions and named
    import thunks are included in the result but NOT recursed into; only their
    first instruction is later collected so references to them show the name.

    Records each function's referrer into `origins` as it goes: the call graph is
    walked here, so this is the only place that knows which instruction reached a
    given callee. `ref_from` is the referrer of `start_ea` itself (None at a seed)."""
    to_export = list()
    stack = [start_ea]
    _record_origin(origins, start_ea, ref_from)

    while stack:
        ea = stack.pop(0)
        func = ida_funcs.get_func(ea) or _NoFunc(ea)
        if not func:
            continue

        func_ea = func.start_ea
        if func_ea in to_export:
            continue

        to_export.append(func_ea)

        # Find all calls from this function
        for head in idautils.FuncItems(func_ea):
            for ref in idautils.XrefsFrom(head, ida_xref.XREF_FAR):
                called_func = ida_funcs.get_func(ref.to)
                if called_func and called_func.start_ea != func_ea:
                    _record_origin(origins, called_func.start_ea, head)
                    stack.append(called_func.start_ea)
                elif not called_func and ref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    _record_origin(origins, ref.to, head)
                    to_export.append(ref.to)

    return to_export


class _NoFunc:
    """Sentinel passed as `cur_func` when scanning a range that is not inside a
    function. Only `.start_ea` is read by the check_* helpers; BADADDR never
    matches a real function start, so nothing is wrongly skipped."""

    def __init__(self, start_ea: ida_idaapi.ea_t = idaapi.BADADDR):
        self.start_ea = start_ea
        self.end_ea = idaapi.BADADDR
        self.flags = 0


_NO_FUNC = _NoFunc()


def _is_range_covered(existing, new_start: int, new_end: int) -> bool:
    """True if any (start, end) pair in `existing` fully covers
    [new_start, new_end) -- i.e. start <= new_start and new_end <= end."""
    for s, e in existing:
        if s <= new_start and new_end <= e:
            return True
    return False


def _scan_worklist(
    all_ranges: list,
    cur_func,
    collected: list,
    funcs_to_export: list,
    processed_ranges: set,
    origins: dict,
):
    """Drain a worklist of ranges, recording each into `collected` and appending
    newly discovered code/data ranges (back onto `all_ranges`) and referenced
    functions (onto `funcs_to_export`). `cur_func` is the function the seed
    ranges belong to (or `_NO_FUNC` for loose ranges).

    `origins` is filled in by the check_* helpers as they discover ranges; it is
    write-only here, so provenance cannot influence what gets collected."""
    while len(all_ranges) > 0:
        r = all_ranges.pop(0)
        start, end = r.start_ea, r.end_ea
        if start >= end:
            continue
        if _is_range_covered(processed_ranges, start, end):
            continue

        collected.append((start, end))

        flags = ida_bytes.get_flags(start)
        if ida_bytes.is_code(flags):
            if start >= cur_func.start_ea and end <= cur_func.end_ea and cur_func.end_ea != idaapi.BADADDR:
                check_c_ref_range(all_ranges, ida_bytes.prev_head(end, start), (start, end), cur_func, funcs_to_export, processed_ranges, origins)
            else:
                for head in idautils.Heads(start, end):
                    check_c_ref_range(all_ranges, head, (start, end), cur_func, funcs_to_export, processed_ranges, origins)
            check_o_ref_range(all_ranges, (start, end), cur_func, funcs_to_export, processed_ranges, origins)
        else:
            check_d_ref_range(all_ranges, (start, end), cur_func, funcs_to_export, processed_ranges, origins)

        processed_ranges.add((start, end))


def _scan_func_ranges(func, collected: list, funcs_to_export: list, processed_ranges: set, origins: dict):
    """Scan a single function's ranges via the shared worklist driver."""
    all_ranges = []
    if func.end_ea == ida_idaapi.BADADDR:
        for s, e in reconstruct_func_range(func.start_ea):
            if not _is_range_covered(processed_ranges, s, e):
                all_ranges.append(ida_range.range_t(s, e))
    else:
        ranges = ida_range.rangeset_t()  # ty:ignore[missing-argument]
        ida_funcs.get_func_ranges(ranges, func)
        all_ranges = [ranges.getrange(i) for i in range(ranges.nranges())]
    all_ranges.sort(key=lambda r: (0 if r.start_ea == func.start_ea else 1, r.start_ea))
    # These chunks come from IDA's function extents, not from a reference, so no
    # check_* helper recorded them. Attribute them to whatever referenced the
    # function -- already in `origins` from the call-graph walk, and absent for a
    # seed. The chunk starting at func.start_ea keeps its own entry either way.
    seed_ref = origins.get(func.start_ea)
    for r in all_ranges:
        _record_origin(origins, r.start_ea, seed_ref)
    _scan_worklist(all_ranges, func, collected, funcs_to_export, processed_ranges, origins)


def _collect_stub_range(func, collected: list, processed_ranges: set):
    """Collect only the first instruction of a library/thunk function, so that
    references to it resolve to its name without pulling in the whole function
    or recursing into it."""
    start = func.start_ea
    end = ida_bytes.get_item_end(start)
    if end <= start:
        return
    if (start, end) in processed_ranges:
        return
    collected.append((start, end))
    processed_ranges.add((start, end))


def _drain_functions(funcs_to_export: list, collected: list, processed_ranges: set, origins: dict):
    """Process every function on the worklist (which grows as references are
    discovered). Regular functions are scanned in full; library functions and
    named import thunks contribute only their first instruction."""
    processed_funcs = set()
    while len(funcs_to_export) > 0:
        if ida_kernwin.user_cancelled():
            break
        ea = funcs_to_export.pop(0)
        if ea in processed_funcs:
            continue
        func = ida_funcs.get_func(ea) or _NoFunc(ea)
        processed_funcs.add(func.start_ea)
        _scan_func_ranges(func, collected, funcs_to_export, processed_ranges, origins)


# The three collectors below take `origins` as a caller-owned dict rather than
# returning it, so their (start, end) return value stays what every caller
# already expects. Pass {} when the provenance is not wanted.


def collect_recursive_ranges(start_ea, origins: dict | None = None) -> list:
    """Collect the range of the function at `start_ea` plus all code/data ranges
    it references, recursively following the discovered functions/ranges.

    Returns a list of (start_ea, end_ea) tuples. `origins`, if given, is filled
    with {discovered start: referring address}; `start_ea` is the seed and so
    never appears in it."""
    if origins is None:
        origins = {}
    funcs_to_export = get_recursive_functions(start_ea, origins)
    processed_ranges = set()
    collected = []
    _drain_functions(funcs_to_export, collected, processed_ranges, origins)
    return collected


def collect_recursive_ranges_from_range(start, end, origins: dict | None = None) -> list:
    """Like `collect_recursive_ranges`, but seeded from an arbitrary range
    instead of a function. Used when an existing range is edited: the new range
    is scanned for references and everything reachable is collected.

    The seed range itself is included in the result."""
    if origins is None:
        origins = {}
    processed_ranges = set()
    funcs_to_export = []
    collected = []
    cur_func = ida_funcs.get_func(start) or _NoFunc(start)
    _scan_worklist(
        [ida_range.range_t(start, end)],
        cur_func,
        collected,
        funcs_to_export,
        processed_ranges,
        origins,
    )
    _drain_functions(funcs_to_export, collected, processed_ranges, origins)
    return collected


def collect_recursive_ranges_from_ranges(seed_ranges, origins: dict | None = None) -> list:
    """Like `collect_recursive_ranges_from_range`, but seeded from several loose
    ranges at once (e.g. the blocks returned by `reconstruct_func_range` for a
    function IDA never defined). The seeds are treated as not belonging to any
    function (`_NO_FUNC`); each is scanned for references and everything
    reachable is collected. The seed ranges themselves are included."""
    if origins is None:
        origins = {}
    processed_ranges = set()
    funcs_to_export = []
    collected = []
    seeds = [ida_range.range_t(s, e) for s, e in seed_ranges if s < e]
    _scan_worklist(seeds, _NO_FUNC, collected, funcs_to_export, processed_ranges, origins)
    _drain_functions(funcs_to_export, collected, processed_ranges, origins)
    return collected


# --- UI Components ---


def _qt_flags(*flags):
    """OR Qt flags together without tripping IDA's PyQt5 shim.

    When something in the session imports PyQt5, IDA's shim (PyQt5/utils.py)
    replaces __or__ on every PySide6 enum that is not already an IntEnum/IntFlag.
    The replacement warns (RuntimeWarning) even when both operands are the same
    enum type, so a plain `A | B` is enough to trigger it. Despite the name of
    the shim's warn_once_per_module(), the dedupe is Python's default filter,
    which keys on source line -- so every OR site reports separately.

    Only enums whose base is Flag need this. Checked against IDA 9.3's bundled
    PySide6 6.8.0: QDialogButtonBox.StandardButton and
    QAbstractItemView.EditTrigger are Flag and do need it, while
    QMessageBox.StandardButton is an IntFlag and ORs natively without warning.
    Only __or__ is patched, so `&` and `~` on Qt flags are fine either way."""
    combined = 0
    for f in flags:
        combined |= f.value
    return type(flags[0])(combined)


class _SizeItem(QtWidgets.QTableWidgetItem):
    """Size cell: shows "0x64 (100)" but hands the editor just "0x64".

    QTableWidgetItem aliases DisplayRole onto EditRole, so without this override
    an inline edit would start with the whole composite string for the user to
    clear and retype."""

    def __init__(self, size):
        super().__init__(f"{hex(size)} ({size})")
        self._edit_text = hex(size)

    def data(self, role):
        if role == QtCore.Qt.ItemDataRole.EditRole:
            return self._edit_text
        return super().data(role)


class SlicerTable(QtWidgets.QTableWidget):
    COL_NAME, COL_START, COL_END, COL_SIZE, COL_REF, COL_ATTRS, COL_SIG = range(7)

    def __init__(self, plugin, parent=None):
        super(SlicerTable, self).__init__(parent)
        self.plugin = plugin
        self._filter_text = ""
        self.setColumnCount(7)
        self.setHorizontalHeaderLabels(["Name", "Start", "End", "Size", "Ref", "Attributes", "Sig"])
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        # Deliberately without AnyKeyPressed: Delete on a selected row deletes
        # entries (see keyPressEvent), so stray typing must not open an editor.
        self.setEditTriggers(_qt_flags(QtWidgets.QAbstractItemView.EditTrigger.DoubleClicked, QtWidgets.QAbstractItemView.EditTrigger.EditKeyPressed))
        self._pending_jump = None
        self._jump_timer = QtCore.QTimer(self)
        self._jump_timer.setSingleShot(True)
        self._jump_timer.timeout.connect(self._do_pending_jump)
        self.customContextMenuRequested.connect(self.show_context_menu)
        self.cellClicked.connect(self.on_cell_clicked)
        self.cellDoubleClicked.connect(self.on_cell_double_clicked)
        self.itemChanged.connect(self.on_item_changed)

    @property
    def entries(self):
        return self.plugin.entries

    def add_entry(self, entry):
        self.entries.append(entry)
        self.refresh()
        self.plugin.save_config()

    def refresh(self):
        # setItem emits itemChanged, so rebuilding the table would otherwise
        # feed every display string back through on_item_changed as if the user
        # had typed it.
        self.blockSignals(True)
        try:
            self.setRowCount(0)
            for i, entry in enumerate(self.entries):
                self.insertRow(i)
                self.setItem(i, self.COL_NAME, QtWidgets.QTableWidgetItem(entry.name))
                self.setItem(i, self.COL_START, QtWidgets.QTableWidgetItem(hex(entry.start)))
                self.setItem(i, self.COL_END, QtWidgets.QTableWidgetItem(hex(entry.end)))
                self.setItem(i, self.COL_SIZE, _SizeItem(entry.size()))

                perm_str = ""
                perm_str += "R" if entry.perm & ida_segment.SEGPERM_READ else "."
                perm_str += "W" if entry.perm & ida_segment.SEGPERM_WRITE else "."
                perm_str += "X" if entry.perm & ida_segment.SEGPERM_EXEC else "."
                attr_str = f"{perm_str} | T:{entry.seg_type} | A:{entry.align}"
                if entry.recursive:
                    attr_str += " | rec"

                # Ref records where the scan found this range and means nothing
                # if retyped; Attributes is a composite rendering; Sig is derived
                # from the bytes. None round-trips through a text editor, so all
                # three stay read-only.
                ref_item = QtWidgets.QTableWidgetItem(_ref_label(entry.ref))
                if entry.ref is not None:
                    ref_item.setToolTip("Click to jump to the reference that pulled this range in.")
                for col, item in (
                    (self.COL_REF, ref_item),
                    (self.COL_ATTRS, QtWidgets.QTableWidgetItem(attr_str)),
                    (self.COL_SIG, QtWidgets.QTableWidgetItem(entry.sig)),
                ):
                    item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
                    self.setItem(i, col, item)
        finally:
            self.blockSignals(False)
        self.apply_filter(self._filter_text)

    def on_item_changed(self, item):
        """Commit an inline cell edit back onto the entry. Anything unparseable
        or out of order reverts, by rebuilding the row from the entry it failed
        to change."""
        row, col = item.row(), item.column()
        if row >= len(self.entries):
            return
        entry = self.entries[row]
        text = item.text().strip()
        old_start, old_end = entry.start, entry.end

        if col == self.COL_NAME:
            if not text:
                print("[IDASlicer] Name cannot be empty.")
                self.refresh()
                return
            entry.name = text
        elif col in (self.COL_START, self.COL_END, self.COL_SIZE):
            try:
                value = int(text, 0)
            except ValueError:
                print(f"[IDASlicer] Not a hex value: {text!r}")
                self.refresh()
                return
            if value < 0:
                print(f"[IDASlicer] Negative value: {text!r}")
                self.refresh()
                return
            if col == self.COL_START:
                if value > entry.end:
                    print(f"[IDASlicer] Start {hex(value)} is past End {hex(entry.end)}.")
                    self.refresh()
                    return
                entry.start = value
            elif col == self.COL_END:
                if value < entry.start:
                    print(f"[IDASlicer] End {hex(value)} is before Start {hex(entry.start)}.")
                    self.refresh()
                    return
                entry.end = value
            else:
                entry.end = entry.start + value
            entry.update_sig()
        else:
            return

        self.refresh()
        self.plugin.save_config()

        # Same rule as the Edit dialog: a recursive entry whose range moved gets
        # its new range scanned for references.
        if entry.recursive and (entry.start, entry.end) != (old_start, old_end):
            self.plugin.rescan_range_entry(entry)

    def apply_filter(self, text):
        """Hide rows where no column contains `text` (case-insensitive)."""
        self._filter_text = text or ""
        needle = self._filter_text.lower()
        for row in range(self.rowCount()):
            hit = not needle
            if not hit:
                for col in range(self.columnCount()):
                    item = self.item(row, col)
                    if item and needle in item.text().lower():
                        hit = True
                        break
            self.setRowHidden(row, not hit)

    def on_cell_clicked(self, row, col):
        """Clicking the Start, End or Ref cell jumps the IDA view to that address.

        Qt delivers the first click of a double click as an ordinary click, so
        jumping right here would navigate away every time the user double clicks
        the cell to edit it. Hold the jump for the double-click interval instead;
        `on_cell_double_clicked` cancels it if the second click arrives. The cost
        is that a real single click navigates that much later.

        The address comes off the entry rather than the cell text: Ref renders as
        "0x1234 (sub_1000+0x8)", which no int() parse would survive."""
        if row >= len(self.entries):
            return
        entry = self.entries[row]
        ea = {self.COL_START: entry.start, self.COL_END: entry.end, self.COL_REF: entry.ref}.get(col)
        if ea is None:
            return
        self._pending_jump = ea
        self._jump_timer.start(QtWidgets.QApplication.doubleClickInterval())

    def on_cell_double_clicked(self, row, col):
        """The cell editor is opening -- drop the jump the first click queued."""
        self._jump_timer.stop()
        self._pending_jump = None

    def _do_pending_jump(self):
        ea = self._pending_jump
        self._pending_jump = None
        if ea is None:
            return
        # The End value is an exclusive bound, so it often points one past the
        # last mapped byte (unmapped). Back up to the last mapped address so the
        # jump lands somewhere valid instead of failing.
        if not ida_bytes.is_mapped(ea):
            prev = ida_bytes.prev_addr(ea)
            if prev != idaapi.BADADDR:
                ea = prev
        ida_kernwin.jumpto(ea)

    def show_context_menu(self, pos):
        selected_rows = [index.row() for index in self.selectionModel().selectedRows()]
        if not selected_rows:
            return

        menu = QtWidgets.QMenu()
        edit_action = None
        if len(selected_rows) == 1:
            edit_action = menu.addAction("Edit")
        recreate_action = menu.addAction("Recreate function")
        delete_action = menu.addAction("Delete")

        action = menu.exec(self.mapToGlobal(pos))
        if edit_action and action == edit_action:
            self.edit_entry(selected_rows[0])
        elif action == recreate_action:
            self.recreate_functions(selected_rows)
        elif action == delete_action:
            self.delete_entries(selected_rows)

    def recreate_functions(self, rows):
        """Undefine the code in each selected range, then (re)create a function
        at the range start. Useful when IDA's auto-analysis got the function
        bounds wrong and the slice range carries the intended extent."""
        for row in rows:
            entry = self.entries[row]
            start, end = entry.start, entry.end
            size = end - start
            if size <= 0:
                continue
            # Drop any function already covering the start so add_func can
            # redefine it cleanly, then undefine the whole range.
            existing = ida_funcs.get_func(start)
            if existing is not None:
                ida_funcs.del_func(existing.start_ea)
            ida_bytes.del_items(start, ida_bytes.DELIT_SIMPLE, size)
            if not ida_funcs.add_func(start, end):
                # Fall back to letting IDA pick the end if explicit bounds fail.
                ida_funcs.add_func(start)
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)

    def delete_entries(self, rows):
        # Sort rows in reverse order to pop from the end to keep indices valid
        for row in sorted(rows, reverse=True):
            self.entries.pop(row)
        self.refresh()
        self.plugin.save_config()

    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key.Key_Delete:
            selected_rows = [index.row() for index in self.selectionModel().selectedRows()]
            if selected_rows:
                self.delete_entries(selected_rows)
        else:
            super(SlicerTable, self).keyPressEvent(event)

    def edit_entry(self, row):
        entry = self.entries[row]
        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Edit Entry")
        layout = QtWidgets.QFormLayout(dialog)

        name_edit = QtWidgets.QLineEdit(entry.name)
        start_edit = QtWidgets.QLineEdit(hex(entry.start))
        end_edit = QtWidgets.QLineEdit(hex(entry.end))
        size_edit = QtWidgets.QLineEdit(hex(entry.size()))
        perm_edit = QtWidgets.QLineEdit(str(entry.perm))
        type_edit = QtWidgets.QLineEdit(str(entry.seg_type))
        align_edit = QtWidgets.QLineEdit(str(entry.align))
        recursive_check = QtWidgets.QCheckBox("Re-scan references when the range changes")
        recursive_check.setChecked(entry.recursive)

        # Size is a derived view of End: typing a size moves End, while editing
        # Start or End recomputes Size. End stays the authoritative field that
        # the accept handler below reads. These connect to textEdited rather
        # than textChanged because textEdited does not fire on setText(), so the
        # two handlers cannot retrigger each other.
        def _parse_hex(text):
            try:
                return int(text.strip(), 16)
            except ValueError:
                return None

        def sync_end_from_size(_text=None):
            start = _parse_hex(start_edit.text())
            size = _parse_hex(size_edit.text())
            if start is None or size is None or size < 0:
                return
            end_edit.setText(hex(start + size))

        def sync_size_from_end(_text=None):
            start = _parse_hex(start_edit.text())
            end = _parse_hex(end_edit.text())
            if start is None or end is None or end < start:
                return
            size_edit.setText(hex(end - start))

        size_edit.textEdited.connect(sync_end_from_size)
        end_edit.textEdited.connect(sync_size_from_end)
        start_edit.textEdited.connect(sync_size_from_end)

        layout.addRow("Name:", name_edit)
        layout.addRow("Start (hex):", start_edit)
        layout.addRow("End (hex):", end_edit)
        layout.addRow("Size (hex):", size_edit)
        layout.addRow("Permissions (int):", perm_edit)
        layout.addRow("Type (int):", type_edit)
        layout.addRow("Alignment (int):", align_edit)
        layout.addRow("Recursive:", recursive_check)

        buttons = QtWidgets.QDialogButtonBox(
            _qt_flags(QtWidgets.QDialogButtonBox.StandardButton.Ok, QtWidgets.QDialogButtonBox.StandardButton.Cancel)
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)

        if dialog.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            try:
                old_start, old_end = entry.start, entry.end
                entry.name = name_edit.text()
                entry.start = int(start_edit.text(), 16)
                entry.end = int(end_edit.text(), 16)
                entry.perm = int(perm_edit.text())
                entry.seg_type = int(type_edit.text())
                entry.align = int(align_edit.text())
                entry.recursive = recursive_check.isChecked()
                entry.update_sig()
            except ValueError:
                QtWidgets.QMessageBox.warning(self, "Error", "Invalid input format.")
                return

            self.refresh()
            self.plugin.save_config()

            # If this is a recursive entry and its range changed, scan the new
            # range for references and add any newly discovered ranges.
            if entry.recursive and (entry.start, entry.end) != (old_start, old_end):
                self.plugin.rescan_range_entry(entry)


class SettingsDialog(QtWidgets.QDialog):
    """Scanner tuning, kept out of the entry Edit dialog because these apply to
    the scan itself rather than to any one range."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("IDASlicer Settings")
        layout = QtWidgets.QFormLayout(self)

        self.explore_spin = QtWidgets.QSpinBox()
        self.explore_spin.setRange(0, 0x100000)
        self.explore_spin.setSuffix(" bytes")
        self.explore_spin.setValue(SETTINGS["max_explore_len"])
        self.explore_spin.setToolTip(
            "When a reference lands on data whose extent IDA has not defined, adjacent\n"
            "unnamed items are glued together until the span reaches this length. It is\n"
            "a threshold, not a hard cap: the item that crosses the line is taken whole,\n"
            "so a range can end past it. The walk also stops early at a named address,\n"
            "at unmapped memory, or at the end of a BSS item.\n"
            "\n"
            "0 takes only the item at the target address.\n"
            "Raise it when referenced blobs come out truncated; lower it when scans\n"
            "swallow neighbouring data."
        )

        self.skip_named_check = QtWidgets.QCheckBox("Skip data that already has a name")
        self.skip_named_check.setChecked(SETTINGS["skip_named_data"])
        self.skip_named_check.setToolTip(
            "Do not pull in referenced data that carries a name. Shrinks a slice by\n"
            "leaving named globals out, at the cost of references to them landing on\n"
            "addresses the slice does not contain."
        )

        layout.addRow("Loose data explore length:", self.explore_spin)
        layout.addRow("", self.skip_named_check)

        hint = QtWidgets.QLabel("Applies to later scans. Entries already in the list keep the ranges they were collected with.")
        hint.setWordWrap(True)
        hint.setEnabled(False)
        layout.addRow(hint)

        standard = QtWidgets.QDialogButtonBox.StandardButton
        buttons = QtWidgets.QDialogButtonBox(_qt_flags(standard.Ok, standard.Cancel, standard.RestoreDefaults))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        buttons.button(standard.RestoreDefaults).clicked.connect(self.restore_defaults)
        layout.addRow(buttons)

    def restore_defaults(self):
        self.explore_spin.setValue(DEFAULT_SETTINGS["max_explore_len"])
        self.skip_named_check.setChecked(DEFAULT_SETTINGS["skip_named_data"])

    def values(self):
        return {
            "max_explore_len": self.explore_spin.value(),
            "skip_named_data": self.skip_named_check.isChecked(),
        }


class SlicerPluginForm(ida_kernwin.PluginForm):
    def __init__(self, plugin):
        super(SlicerPluginForm, self).__init__()
        self.plugin = plugin

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.layout = QtWidgets.QVBoxLayout(self.parent)

        search_layout = QtWidgets.QHBoxLayout()
        search_layout.addWidget(QtWidgets.QLabel("Search:"))
        self.search_edit = QtWidgets.QLineEdit()
        self.search_edit.setPlaceholderText("Filter rows by any field...")
        self.search_edit.setClearButtonEnabled(True)
        search_layout.addWidget(self.search_edit)
        self.settings_button = QtWidgets.QPushButton("Settings")
        self.settings_button.clicked.connect(self.on_settings_clicked)
        search_layout.addWidget(self.settings_button)
        self.layout.addLayout(search_layout)

        self.table = SlicerTable(self.plugin)
        self.search_edit.textChanged.connect(self.table.apply_filter)
        self.layout.addWidget(self.table)
        self.table.refresh()

        type_layout = QtWidgets.QHBoxLayout()
        type_layout.addWidget(QtWidgets.QLabel("File Type:"))
        self.type_edit = QtWidgets.QLineEdit()
        self.type_edit.setText(self.plugin.detect_file_type())
        type_layout.addWidget(self.type_edit)
        self.layout.addLayout(type_layout)

        self.slice_button = QtWidgets.QPushButton("Slice and Create IDA Database")
        self.slice_button.clicked.connect(self.on_slice_clicked)
        self.layout.addWidget(self.slice_button)

        self.merge_check = QtWidgets.QCheckBox("Merge all ranges into a single .seg file")
        self.layout.addWidget(self.merge_check)

        self.save_seg_button = QtWidgets.QPushButton("Save segments to .seg files")
        self.save_seg_button.clicked.connect(self.on_save_seg_clicked)
        self.layout.addWidget(self.save_seg_button)

        self.import_seg_button = QtWidgets.QPushButton("Import .seg files")
        self.import_seg_button.clicked.connect(self.on_import_seg_clicked)
        self.layout.addWidget(self.import_seg_button)

    def on_settings_clicked(self):
        dialog = SettingsDialog(self.parent)
        if dialog.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            SETTINGS.update(dialog.values())
            self.plugin.save_config()

    def OnClose(self, form):
        # IDA destroys the Qt widgets when the form closes, but this Python
        # object survives. Drop the plugin's reference so later refreshes are
        # skipped and the next Show() builds a fresh form, instead of reaching
        # through to an already-deleted QTableWidget.
        self.plugin.form = None

    def on_slice_clicked(self):
        if not ida_domain:
            QtWidgets.QMessageBox.critical(
                self.parent,
                "Error",
                "IDA Domain API not found. This feature requires IDA Pro 9.1 or later.",
            )
            return

        file_type_str = self.type_edit.text().strip()
        if not file_type_str:
            QtWidgets.QMessageBox.warning(self.parent, "Error", "Please enter a file type.")
            return

        self.plugin.perform_slice(self.table.entries, file_type_str)

    def on_save_seg_clicked(self):
        self.plugin.save_segments_to_files(self.table.entries, merge=self.merge_check.isChecked())

    def on_import_seg_clicked(self):
        self.plugin.import_segments_from_files()

    def add_entry(self, entry):
        self.table.add_entry(entry)


# --- Actions ---


class AddToSlicerHandler(ida_kernwin.action_handler_t):
    def __init__(self, plugin, mode):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin
        self.mode = mode

    def activate(self, ctx):
        if self.mode == "function_recursive":
            ea = ctx.cur_ea
            func = ida_funcs.get_func(ea)
            if func:
                self.plugin.add_function_recursive(func.start_ea)
            else:
                # IDA hasn't defined a function here: reconstruct its extent by
                # flooding control flow, then seed the recursive scan from it.
                blocks = reconstruct_func_range(ea)
                if not blocks:
                    print("Could not reconstruct a function range at current address.")
                    return 0
                self.plugin.add_ranges_recursive(blocks)
            return 1
        if self.mode == "function":
            ea = ctx.cur_ea
            func = ida_funcs.get_func(ea)
            blocks = []
            # Non-recursive mode still reaches referenced data through
            # check_o_ref_range, so those blocks do have a referrer worth showing.
            # The function's own chunks have none, and stay blank.
            origins = {}
            if func:
                funcs_to_export = [func.start_ea]
                processed_ranges = set()
                _drain_functions(funcs_to_export, blocks, processed_ranges, origins)
            else:
                # No IDA function: reconstruct the full extent (code blocks +
                # embedded data) by flooding control flow. This may yield several
                # disjoint blocks (a far jump leaves a code gap unbridged), so
                # add each as its own entry instead of one giant span.
                blocks = reconstruct_func_range(ea)
                if not blocks:
                    print("Could not reconstruct a function range at current address.")
                    return 0
            for s, e in blocks:
                bseg = ida_segment.getseg(s)
                if not bseg:
                    continue
                self.plugin.add_to_list(SlicerEntry(self.plugin._range_name(s, bseg), s, e, bseg.perm, bseg.type, bseg.align, ref=origins.get(s)))
            return 1
        elif self.mode == "segment":
            ea = ctx.cur_ea
            seg = ida_segment.getseg(ea)
            if not seg:
                print("No segment at current address.")
                return 0
            start, end = seg.start_ea, seg.end_ea
        else:
            # Try to get selection
            success, start, end = ida_kernwin.read_range_selection(ctx.widget)
            if not success:
                # No selection, use current address
                start = ctx.cur_ea
                # Get the size of the item at current address (instruction or data)
                item_size = ida_bytes.get_item_size(start)
                end = start + item_size
                print(f"No selection, adding current item at {hex(start)} (size {item_size})")

        seg = ida_segment.getseg(start)
        if not seg:
            print("Address not in segment.")
            return 0

        # Function name for code inside a function, else "{segment}_{addr}".
        name = self.plugin._range_name(start, seg)
        perm = seg.perm
        seg_type = seg.type
        align = seg.align

        entry = SlicerEntry(name, start, end, perm, seg_type, align)
        self.plugin.add_to_list(entry)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_DISASM else ida_kernwin.AST_DISABLE_FOR_WIDGET


# --- Main Plugin ---


class IDASlicerPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MOD
    comment = "Slices functions/selections/segments into a new IDA database."
    help = "Right-click in IDA View to add to slicer list."
    wanted_name = "IDASlicer"
    wanted_hotkey = ""

    def init(self):
        self.form = None
        self.entries = []
        self.last_import_path = ""
        self.load_config()
        self.register_actions()
        self.hooks = SlicerUIHooks(self)  # ty:ignore[missing-argument]
        self.hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def _get_config_path(self):
        # Store in the same directory as the plugin
        return os.path.join(os.path.dirname(os.path.realpath(__file__)), "idaslicer_config.json")

    def load_config(self):
        path = self._get_config_path()
        if not os.path.exists(path):
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                config = json.load(f)

            self.last_import_path = config.get("last_import_path", "")
            _apply_stored_settings(config.get("settings"))

            md5 = ida_nalt.retrieve_input_file_md5()
            if md5:
                md5_hex = md5.hex()
                entries_data = config.get("entries", {}).get(md5_hex, [])
                self.entries = [SlicerEntry.from_dict(d) for d in entries_data]

            if self.form and hasattr(self.form, "table"):
                self.form.table.refresh()
        except Exception as e:
            print(f"Failed to load IDASlicer config: {e}")

    def save_config(self):
        path = self._get_config_path()
        config = {"entries": {}, "last_import_path": self.last_import_path, "settings": dict(SETTINGS)}

        # Load existing config to preserve other MD5s
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    config = json.load(f)
            except:  # noqa: E722
                pass

        config["last_import_path"] = self.last_import_path
        config["settings"] = dict(SETTINGS)

        md5 = ida_nalt.retrieve_input_file_md5()
        if md5:
            md5_hex = md5.hex()
            if "entries" not in config:
                config["entries"] = {}
            config["entries"][md5_hex] = [e.to_dict() for e in self.entries]  # ty:ignore[invalid-assignment]

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"Failed to save IDASlicer config: {e}")

    def term(self):
        self.unregister_actions()
        if hasattr(self, "hooks"):
            self.hooks.unhook()

    def run(self, arg):
        self.load_config()
        if not self.form:
            self.form = SlicerPluginForm(self)  # ty:ignore[missing-argument]
        self.form.Show("Slicer List")
        if self.form:
            self.form.table.refresh()

    def register_actions(self):
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "idaslicer:add_func",
                "Add function to slicer",
                AddToSlicerHandler(self, "function"),  # ty:ignore[too-many-positional-arguments]
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "idaslicer:add_func_recursive",
                "Add function recursively to slicer",
                AddToSlicerHandler(self, "function_recursive"),  # ty:ignore[too-many-positional-arguments]
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "idaslicer:add_sel",
                "Add selection to slicer",
                AddToSlicerHandler(self, "selection"),  # ty:ignore[too-many-positional-arguments]
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "idaslicer:add_seg",
                "Add current segment to slicer",
                AddToSlicerHandler(self, "segment"),  # ty:ignore[too-many-positional-arguments]
            )
        )

    def unregister_actions(self):
        ida_kernwin.unregister_action("idaslicer:add_func")
        ida_kernwin.unregister_action("idaslicer:add_func_recursive")
        ida_kernwin.unregister_action("idaslicer:add_sel")
        ida_kernwin.unregister_action("idaslicer:add_seg")

    def add_to_list(self, entry):
        self.entries.append(entry)
        self.save_config()
        if self.form:
            self.form.table.refresh()

    @staticmethod
    def _apply_seg_attrs(s, seg_type, align):
        """Apply numeric segment type and alignment to a freshly created segment.
        Takes the segment handle its caller just created rather than looking one
        up by address, so it can never land on a neighbouring segment that
        already existed. No-op when these were not recorded in the payload
        (None)."""
        if seg_type is None and align is None:
            return
        if not s:
            return
        if seg_type is not None:
            s.type = seg_type  # ty:ignore[invalid-assignment]
        if align is not None:
            s.align = align  # ty:ignore[invalid-assignment]
        s.update()

    @staticmethod
    def _range_name(start, seg):
        """Name a range so it is easy to identify and naturally unique.
        The base is the containing function name (for code inside a function)
        or the segment name otherwise; the start address is always appended so
        that several ranges sharing the same function/segment (e.g. multiple
        selections within one function) never collide."""
        base = None
        flags = ida_bytes.get_flags(start)
        if ida_bytes.is_code(flags):
            func = ida_funcs.get_func(start)
            if func:
                base = ida_funcs.get_func_name(func.start_ea)
        if not base:
            base = ida_segment.get_segm_name(seg)
        return f"{base}_{hex(start)}"

    def _add_collected_ranges(self, ranges, origins=None):
        """Fold a scan's (start, end) ranges into the slicer list, merging them
        with each other *and* with the entries already listed — the same whole-list
        merge the importer does, so a discovery that abuts an existing entry
        extends it instead of adding a second row. Returns
        `(added, extended)`: new rows, and existing rows whose range grew. Does
        not save/refresh — the caller does.

        `origins` supplies each range's referring address for the Ref column."""
        origins = origins or {}
        existing = [(e.start, e.end) for e in self.entries]
        # Keyed by identity, and holding the entry itself so no id() can be
        # recycled while the comparison below is still pending.
        ends_before = {id(e): (e, e.end) for e in self.entries}

        def _contained(s, e, others):
            for cs, ce in others:
                if cs <= s and e <= ce:
                    return True
            return False

        # Merge the batch first: a scan turns up many adjacent slivers (a
        # function's chunks, a pointer table walked item by item) that would each
        # otherwise become their own row and their own segment on export/import.
        # Runs already covered by an existing entry are dropped here rather than
        # in the whole-list merge below -- they cannot change its outcome, and
        # skipping them avoids building a SlicerEntry (and hashing its bytes) only
        # to throw it away. A run's start is always one of the original starts, so
        # `origins` and `_range_name` still resolve.
        candidates = []
        for start, end in _merge_intervals((s, e) for s, e in ranges if s < e):
            if _contained(start, end, existing):
                continue
            seg = ida_segment.getseg(start)
            if not seg:
                continue
            name = self._range_name(start, seg)
            candidates.append(SlicerEntry(name, start, end, seg.perm, seg.type, seg.align, recursive=True, ref=origins.get(start)))

        if not candidates:
            return 0, 0

        # Existing entries first, so a hand-edited entry outranks a fresh
        # discovery starting at the same address.
        before = len(self.entries)
        self.entries = _merge_entries(self.entries + candidates)
        extended = sum(1 for e in self.entries if id(e) in ends_before and e.end != ends_before[id(e)][1])
        return len(self.entries) - before, extended

    def add_function_recursive(self, start_ea: int):
        """Add the function at start_ea and every code/data range it references
        (recursively) to the slicer list."""
        ida_kernwin.show_wait_box("Scanning recursive references...")
        origins = {}
        try:
            ranges = collect_recursive_ranges(start_ea, origins)
        except Exception as e:
            ida_kernwin.hide_wait_box()
            print(f"[IDASlicer] Recursive scan failed: {e}")
            QtWidgets.QMessageBox.critical(None, "Error", f"Recursive scan failed:\n{e}")
            return
        finally:
            ida_kernwin.hide_wait_box()

        added, extended = self._add_collected_ranges(ranges, origins)
        self.save_config()
        if self.form:
            self.form.table.refresh()

        print(f"[IDASlicer] Recursive scan of {hex(start_ea)}: {len(ranges)} ranges found, {added} added / {extended} extended.")
        ida_kernwin.info(_added_msg(added, extended))

    def add_ranges_recursive(self, seed_ranges):
        """Like `add_function_recursive`, but seeded from reconstructed ranges
        instead of an IDA-defined function. Used when IDA has not turned the
        code into a function (see `reconstruct_func_range`)."""
        ida_kernwin.show_wait_box("Scanning recursive references...")
        origins = {}
        try:
            ranges = collect_recursive_ranges_from_ranges(seed_ranges, origins)
        except Exception as e:
            ida_kernwin.hide_wait_box()
            print(f"[IDASlicer] Recursive scan failed: {e}")
            QtWidgets.QMessageBox.critical(None, "Error", f"Recursive scan failed:\n{e}")
            return
        finally:
            ida_kernwin.hide_wait_box()

        added, extended = self._add_collected_ranges(ranges, origins)
        self.save_config()
        if self.form:
            self.form.table.refresh()

        seeds = ", ".join(hex(s) for s, _ in seed_ranges) or "(none)"
        print(f"[IDASlicer] Recursive scan of [{seeds}]: {len(ranges)} ranges found, {added} added / {extended} extended.")
        ida_kernwin.info(_added_msg(added, extended))

    def rescan_range_entry(self, entry):
        """Re-scan an edited recursive entry's range for references and add any
        newly discovered ranges to the slicer list."""
        ida_kernwin.show_wait_box("Re-scanning edited range...")
        origins = {}
        try:
            ranges = collect_recursive_ranges_from_range(entry.start, entry.end, origins)
        except Exception as e:
            ida_kernwin.hide_wait_box()
            print(f"[IDASlicer] Re-scan failed: {e}")
            QtWidgets.QMessageBox.critical(None, "Error", f"Re-scan failed:\n{e}")
            return
        finally:
            ida_kernwin.hide_wait_box()

        added, extended = self._add_collected_ranges(ranges, origins)
        self.save_config()
        if self.form:
            self.form.table.refresh()

        print(f"[IDASlicer] Re-scan of {hex(entry.start)}-{hex(entry.end)}: {len(ranges)} ranges found, {added} added / {extended} extended.")
        if added or extended:
            ida_kernwin.info(_added_msg(added, extended))

    def detect_file_type(self):
        ftype_enum = ida_ida.inf_get_filetype()
        proc_name = ida_ida.inf_get_procname().lower()
        is_64 = ida_ida.inf_is_64bit()
        if proc_name == "metapc":
            proc_name = "x64" if is_64 else "x86"
        elif proc_name == "arm":
            proc_name = "arm64" if is_64 else "arm32"

        ftype_map = {ida_ida.f_ELF: "elf", ida_ida.f_PE: "pe", ida_ida.f_MACHO: "macho"}
        base_ftype = ftype_map.get(ftype_enum, "unknown")
        return f"{base_ftype}_{proc_name}"

    def perform_slice(self, entries: list[SlicerEntry], file_type_str):
        if not entries:
            print("No entries to slice.")
            return

        script_dir = os.path.dirname(os.path.realpath(__file__))
        template_path = os.path.join(script_dir, "obj_minis", f"{file_type_str}.i64")

        if not os.path.exists(template_path):
            print(f"Template not found: {template_path}")
            QtWidgets.QMessageBox.warning(None, "Error", f"Template not found:\n{template_path}")
            return

        input_path = ida_nalt.get_input_file_path()
        out_dir = os.path.dirname(input_path)
        base_name = os.path.basename(input_path)
        out_name = os.path.splitext(base_name)[0] + "_slice.i64"
        out_path = os.path.join(out_dir, out_name)

        try:
            shutil.copy(template_path, out_path)
            print(f"Copied template to {out_path}")
        except Exception as e:
            print(f"Failed to copy template: {e}")
            QtWidgets.QMessageBox.critical(None, "Error", f"Failed to copy template:\n{e}")
            return

        # Prepare data for subprocess
        entries_data = []
        for entry in entries:
            seg_class = get_seg_class(entry.seg_type)
            content = ida_bytes.get_bytes(entry.start, entry.size())
            entries_data.append(
                {
                    "name": entry.name,
                    "start": entry.start,
                    "end": entry.end,
                    "perm": entry.perm,
                    "seg_type": entry.seg_type,
                    "align": entry.align,
                    "seg_class": seg_class,
                    "names": self._collect_names(entry.start, entry.end),
                    "content": content,
                }
            )

        data_fd, data_path = tempfile.mkstemp(suffix=".pickle")
        script_fd, script_path = tempfile.mkstemp(suffix=".py")

        try:
            with os.fdopen(data_fd, "wb") as f:
                pickle.dump((out_path, entries_data), f)

            with os.fdopen(script_fd, "w") as f:
                f.write(WORKER_SCRIPT)

            print(f"Running subprocess for database operations: {out_path}")
            env = os.environ.copy()
            keys_to_remove = [
                "IDA_PYTHON_VERSION",
                "IDA_PATH",
                "IDAPYTHON_VERSION",
                "PYTHONPATH",
                "PYTHONHOME",
            ]
            for key in list(env.keys()):
                if key == "IDADIR":
                    continue
                if "IDA" in key.upper() or key in keys_to_remove:
                    env.pop(key, None)
            if sys.platform == "win32":
                python_exe = os.path.join(sys.prefix, "python.exe")
            else:
                python_exe = os.path.join(sys.prefix, "bin", "python3")

            result = subprocess.run(
                [python_exe, script_path, data_path],
                capture_output=True,
                text=True,
                env=env,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if result.returncode == 0:
                print(f"Slicing complete. Saved to: {out_path}")
                QtWidgets.QMessageBox.information(None, "Success", f"File saved to:\n{out_path}")
            else:
                error_msg = result.stderr or result.stdout
                print(f"Subprocess failed:\n{error_msg}")
                QtWidgets.QMessageBox.critical(None, "Error", f"Subprocess failed:\n{error_msg}")
        except Exception as e:
            print(f"Error during subprocess orchestration: {e}")
            QtWidgets.QMessageBox.critical(None, "Error", f"Error during subprocess orchestration:\n{e}")
        finally:
            if os.path.exists(data_path):
                os.remove(data_path)
            if os.path.exists(script_path):
                os.remove(script_path)

    @staticmethod
    def _collect_names(start, end):
        """Collect user-defined names at every address in [start, end), as a
        list of [offset_from_start, name]. Walks item by item (so named
        undefined bytes are caught too) and skips auto-generated dummy names
        (sub_, loc_, byte_, ...), which IDA regenerates and would only bloat the
        payload."""
        names = []
        ea = start
        while ea < end:
            nm = ida_name.get_name(ea)
            if nm:
                names.append([ea - start, nm])
            nxt = ida_bytes.get_item_end(ea)
            ea = nxt if nxt > ea else ea + 1
        return names

    @staticmethod
    def _build_payload(entry):
        """Build the pickled payload dict for one entry, or None if its bytes
        can't be read."""
        size = entry.size()
        if size <= 0:
            return None
        content = ida_bytes.get_bytes(entry.start, size)
        if content is None:
            print(f"Failed to read bytes at {hex(entry.start)}")
            return None
        entry.update_sig()
        return {
            "version": SEG_FILE_VERSION,
            "name": entry.name,
            "start": entry.start,
            "end": entry.end,
            "perm": entry.perm,
            "seg_type": entry.seg_type,
            "align": entry.align,
            "seg_class": get_seg_class(entry.seg_type),
            "sig": entry.sig,
            "names": IDASlicerPlugin._collect_names(entry.start, entry.end),
            "content": content,
        }

    def save_segments_to_files(self, entries: list[SlicerEntry], merge=False):
        if not entries:
            print("No entries to save.")
            return

        input_path = ida_nalt.get_input_file_path()
        if not input_path:
            print("Could not determine input file path.")
            return

        out_dir = os.path.dirname(input_path)

        payloads = [p for p in (self._build_payload(e) for e in entries) if p]
        if not payloads:
            QtWidgets.QMessageBox.warning(None, "Error", "No ranges with readable bytes to save.")
            return

        if merge:
            # Merging only bundles many ranges into one file for convenient
            # transport/import; every per-range rule (overlap handling, naming,
            # seg attrs, md5) is unchanged - the importer just unpacks the list
            # and processes each payload exactly as a standalone file.
            base = os.path.splitext(os.path.basename(input_path))[0]
            file_path = os.path.join(out_dir, f"{base}_merged.seg")
            merged = {
                "version": SEG_FILE_VERSION,
                "merged": True,
                "entries": payloads,
            }
            try:
                with open(file_path, "wb") as f:
                    pickle.dump(merged, f)
            except Exception as e:
                print(f"Failed to write merged file {file_path}: {e}")
                QtWidgets.QMessageBox.critical(None, "Error", f"Failed to write merged file:\n{e}")
                return
            QtWidgets.QMessageBox.information(None, "Success", f"Saved {len(payloads)} ranges into:\n{file_path}")
            return

        # The filename is purely cosmetic (metadata lives in the payload): name +
        # address range for readability/uniqueness, sanitized and length-capped.
        count = 0
        for payload in payloads:
            name = "".join([c for c in payload["name"] if c not in '<>:"/\\|?*'])
            suffix = f"_{hex(payload['start'])}_{hex(payload['end'])}.seg"
            name = _truncate_filename_name(name, suffix)
            file_path = os.path.join(out_dir, name + suffix)
            try:
                with open(file_path, "wb") as f:
                    pickle.dump(payload, f)
                count += 1
            except Exception as e:
                print(f"Failed to write file {file_path}: {e}")

        QtWidgets.QMessageBox.information(None, "Success", f"Successfully saved {count} segment files to:\n{out_dir}")

    def import_segments_from_files(self):
        if not ida_domain:
            QtWidgets.QMessageBox.critical(
                None,
                "Error",
                "IDA Domain API not found. This feature requires IDA Pro 9.1 or later.",
            )
            return

        files, _ = QtWidgets.QFileDialog.getOpenFileNames(
            None,
            "Select .seg files to import",
            self.last_import_path,
            "Segment files (*.seg)",
        )
        if not files:
            return

        self.last_import_path = os.path.dirname(files[0])
        self.save_config()

        results = []
        imported_entries = []
        existing_ranges = {(e.start, e.end) for e in self.entries}
        overwrite_all = False
        # Every payload has to end up in exactly one of these buckets, so the
        # summary can account for an import that changed nothing. "It did
        # nothing" and "it was never read" look identical without them.
        stats = {"files": len(files), "unreadable": 0, "seen": 0, "invalid": 0, "sig_skipped": 0, "declined": 0, "duplicate": 0, "listed": 0}
        with ida_domain.Database.open(save_on_close=False) as db:
            # segment_t.name is a uval_t index into IDA's name storage, not a
            # string -- the name has to come from the collection accessor.
            existing_names = [db.segments.get_name(s) for s in db.segments]

            def get_unique_name(base_name, current_names):
                if base_name not in current_names:
                    return base_name
                counter = 0
                while f"{base_name}{counter}" in current_names:
                    counter += 1
                return f"{base_name}{counter}"

            # "content" is deliberately not required: a payload that only declares
            # a range carries no bytes, and omitting the key says exactly what an
            # empty one does. The remaining four have no sensible default --
            # without them there is no segment to create.
            required_keys = {"start", "end", "perm", "seg_class"}

            def process_payload(payload, src):
                """Import one range payload. Merging changes nothing here: a
                merged file just yields several payloads, each handled exactly
                like a standalone single-range file."""
                nonlocal overwrite_all
                stats["seen"] += 1
                if not isinstance(payload, dict) or not required_keys.issubset(payload):
                    stats["invalid"] += 1
                    have = sorted(payload) if isinstance(payload, dict) else type(payload).__name__
                    results.append(f"Skipped an invalid payload in {src} (needs {sorted(required_keys)}, has {have})")
                    return

                name = payload.get("name", "")
                start = payload["start"]
                end = payload["end"]
                perm = payload["perm"]
                seg_type = payload.get("seg_type")
                align = payload.get("align")
                seg_class = payload["seg_class"]
                content = payload.get("content") or b""
                expected_sig = payload.get("sig")

                # Strip the original "_{start}" suffix so each created segment can
                # be (re)named "{base}_{its own start}". A single imported range
                # may be split into several segments around existing ones, and
                # naming each by its actual start keeps them unique/identifiable.
                addr_suffix = f"_{hex(start)}"
                base_name = name[: -len(addr_suffix)] if name.endswith(addr_suffix) else name

                # A payload may carry no bytes at all: an externally produced .seg
                # that only *declares* a range. That is not a reason to skip it --
                # the segment still gets created and the range still reaches the
                # slicer list. There is simply nothing to write and nothing to
                # verify, so the byte-level steps below are all guarded on this.
                has_content = bool(content)

                # MD5 Validation
                if has_content and expected_sig:
                    actual_sig = hashlib.md5(content).hexdigest()
                    if actual_sig != expected_sig:
                        msg = f"MD5 mismatch for {base_name or src}!\n\nExpected: {expected_sig}\nActual: {actual_sig}\n\nDo you want to skip this range?"
                        res = QtWidgets.QMessageBox.question(
                            None,
                            "Validation Error",
                            msg,
                            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
                            QtWidgets.QMessageBox.StandardButton.Yes,
                        )
                        if res == QtWidgets.QMessageBox.StandardButton.Yes:
                            stats["sig_skipped"] += 1
                            results.append(f"Skipped '{base_name or src}' at {hex(start)}-{hex(end)}: MD5 mismatch")
                            return

                if has_content and len(content) != (end - start):
                    print(f"Content size mismatch for {base_name or src}")

                # Find all overlapping segments
                overlaps = []
                for s in db.segments:
                    o_start = max(s.start_ea, start)
                    o_end = min(s.end_ea, end)
                    if o_start < o_end:
                        overlaps.append(s)

                overlaps.sort(key=lambda s: s.start_ea)

                # Regions this payload took ownership of below -- bytes written
                # into an existing segment, or a segment created for a gap. A
                # declined overwrite leaves the existing data in place, and step 3
                # must not stamp the imported names onto data it did not import.
                written = []

                # 1. Overwrite overlapping parts
                for s in overlaps:
                    o_start = max(s.start_ea, start)
                    o_end = min(s.end_ea, end)

                    if not has_content:
                        # A byte-less payload claims nothing here: there is no
                        # data to overwrite, so there is no conflict to ask about
                        # and no reason to rename another segment's contents.
                        continue

                    if not overwrite_all:
                        msg_box = QtWidgets.QMessageBox()
                        msg_box.setWindowTitle("Overwrite Conflict")
                        msg_box.setText(
                            f"The range '{base_name}' overlaps with existing segment '{db.segments.get_name(s)}' at {hex(o_start)}-{hex(o_end)}.\n\nDo you want to overwrite the data?"
                        )
                        msg_box.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No)
                        msg_box.setDefaultButton(QtWidgets.QMessageBox.StandardButton.No)

                        cb = QtWidgets.QCheckBox("Apply to all remaining conflicts")
                        msg_box.setCheckBox(cb)

                        res = msg_box.exec()
                        if cb.isChecked():
                            overwrite_all = True

                        if res == QtWidgets.QMessageBox.StandardButton.No:
                            continue

                    offset = o_start - start
                    chunk = content[offset : offset + (o_end - o_start)]
                    db.bytes.set_bytes_at(o_start, chunk)
                    written.append((o_start, o_end))
                    results.append(f"Overwrote part of '{db.segments.get_name(s)}' at {hex(o_start)}-{hex(o_end)}")

                # 2. Create segments for gaps
                current_pos = start
                for s in overlaps:
                    if current_pos < s.start_ea:
                        unique_name = get_unique_name(f"{base_name}_{hex(current_pos)}", existing_names)
                        new_seg = db.segments.add(0, current_pos, s.start_ea, unique_name, seg_class)
                        if new_seg:
                            db.segments.set_permissions(new_seg, perm)
                            self._apply_seg_attrs(new_seg, seg_type, align)
                            if has_content:
                                offset = current_pos - start
                                chunk = content[offset : offset + (s.start_ea - current_pos)]
                                db.bytes.set_bytes_at(current_pos, chunk)
                            written.append((current_pos, s.start_ea))
                            results.append(
                                f"Created segment '{unique_name}' at {hex(current_pos)}-{hex(s.start_ea)}{'' if has_content else ' (no bytes)'}"
                            )
                            existing_names.append(unique_name)
                    current_pos = max(current_pos, s.end_ea)

                if current_pos < end:
                    unique_name = get_unique_name(f"{base_name}_{hex(current_pos)}", existing_names)
                    new_seg = db.segments.add(0, current_pos, end, unique_name, seg_class)
                    if new_seg:
                        db.segments.set_permissions(new_seg, perm)
                        self._apply_seg_attrs(new_seg, seg_type, align)
                        if has_content:
                            offset = current_pos - start
                            chunk = content[offset : offset + (end - current_pos)]
                            db.bytes.set_bytes_at(current_pos, chunk)
                        written.append((current_pos, end))
                        results.append(f"Created segment '{unique_name}' at {hex(current_pos)}-{hex(end)}{'' if has_content else ' (no bytes)'}")
                        existing_names.append(unique_name)

                # 3. Restore names collected from the source database, but only
                # inside the regions claimed above -- never over a segment whose
                # data this payload left untouched.
                for off, nm in payload.get("names", []):
                    ea = start + off
                    if any(ws <= ea < we for ws, we in written):
                        ida_name.set_name(ea, nm, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)

                # 4. Surface the imported range in the slicer list so the user
                # can see what was brought in. Skipped when a payload that *had*
                # bytes wrote none of them: a fully declined overwrite imported
                # nothing, so there is no new range to list. A byte-less payload
                # is listed regardless -- declaring the range is the whole point
                # of it. The signature is re-read from the database, so it
                # reflects what actually landed rather than what was offered.
                if not (written or not has_content):
                    stats["declined"] += 1
                    results.append(f"Imported nothing from '{base_name or src}' at {hex(start)}-{hex(end)}: every overwrite was declined")
                elif (start, end) in existing_ranges:
                    stats["duplicate"] += 1
                else:
                    existing_ranges.add((start, end))
                    stats["listed"] += 1
                    # The payload's perm/type/align describe the *source*
                    # database and are not necessarily right for this one, so
                    # the local segment is the authority. getseg() answers both
                    # cases correctly: a range that already lives in a local
                    # segment yields that segment's real attributes, while a gap
                    # yields the segment created above -- which carries the
                    # payload's values only because nothing local described it.
                    # The payload is the fallback for the one case getseg cannot
                    # answer: no segment was created (add() failed).
                    loc = ida_segment.getseg(start)
                    # The address goes back on. Stripping it above serves the
                    # segments, which may be several and each need their own
                    # start; an entry is the whole range and has exactly one, so
                    # dropping it here would leave every payload named after a
                    # bare base -- three ranges all listed as "unk". Re-appending
                    # also makes the round-trip exact: a name this plugin
                    # exported ends with its own start, so strip+append returns
                    # it unchanged, and it matches `_range_name`'s convention.
                    imported_entries.append(
                        SlicerEntry(
                            f"{base_name}_{hex(start)}" if base_name else f"imported_{hex(start)}",
                            start,
                            end,
                            loc.perm if loc else perm,
                            loc.type if loc else (seg_type if seg_type is not None else 0),
                            loc.align if loc else (align if align is not None else 0),
                        )
                    )

            for file_path in files:
                filename = os.path.basename(file_path)

                try:
                    with open(file_path, "rb") as f:
                        data = pickle.load(f)
                except Exception as e:
                    stats["unreadable"] += 1
                    results.append(f"Failed to read {filename}: {e}")
                    continue

                # A merged file is a wrapper dict carrying a list of payloads; a
                # single-range file is the payload dict itself.
                if isinstance(data, dict) and isinstance(data.get("entries"), list):
                    for payload in data["entries"]:
                        process_payload(payload, filename)
                else:
                    process_payload(data, filename)

        added = extended = absorbed = 0
        if imported_entries:
            # Merge the whole list at once -- existing entries together with every
            # payload of every selected file, not per file and not imports alone.
            # A range split on export, or one that abuts a range already listed,
            # ends up as a single entry instead of a row per fragment. Existing
            # entries come first so that when an import lands on an address
            # already listed, the entry the user may have edited is the one that
            # survives the run. Side effect: the list comes back sorted by start.
            before = len(self.entries)
            ends_before = {id(e): (e, e.end) for e in self.entries}
            self.entries = _merge_entries(self.entries + imported_entries)
            survivors = {id(e) for e in self.entries}
            added = len(self.entries) - before
            extended = sum(1 for e in self.entries if id(e) in ends_before and e.end != ends_before[id(e)][1])
            # An imported entry that is not a row of its own was folded into one:
            # either it stretched an existing entry or it was already covered.
            absorbed = sum(1 for e in imported_entries if id(e) not in survivors)
            self.save_config()
            if self.form:
                self.form.table.refresh()

        # Always report the tally, even when nothing changed. "No changes made."
        # on its own cannot distinguish an import that was fully redundant from
        # one whose files were never parsed, which is exactly when the user needs
        # to know which happened.
        results.append("")
        results.append(f"Read {stats['seen']} payload(s) from {stats['files']} file(s), {stats['unreadable']} unreadable.")
        results.append(
            f"Payloads: {stats['listed']} taken, {stats['invalid']} invalid, "
            f"{stats['sig_skipped']} skipped on MD5, {stats['declined']} declined, {stats['duplicate']} already listed."
        )
        results.append(f"Slicer list: {added} entr{'y' if added == 1 else 'ies'} added, {extended} extended, {absorbed} merged into existing.")

        summary = "\n".join(results)
        # Mirror it to the Output window: the dialog is modal and its contents are
        # gone once dismissed, which makes an import impossible to review after
        # the fact.
        print(f"[IDASlicer] Import summary:\n{summary}")
        QtWidgets.QMessageBox.information(None, "Import Summary", summary)


class SlicerUIHooks(ida_kernwin.UI_Hooks):
    def __init__(self, plugin):
        super(SlicerUIHooks, self).__init__()
        self.plugin = plugin

    def finish_populating_widget_popup(self, widget, popup):  # ty:ignore[invalid-method-override]
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(widget, popup, "idaslicer:add_func", "Add to Slicer/")
            ida_kernwin.attach_action_to_popup(widget, popup, "idaslicer:add_func_recursive", "Add to Slicer/")
            ida_kernwin.attach_action_to_popup(widget, popup, "idaslicer:add_sel", "Add to Slicer/")
            ida_kernwin.attach_action_to_popup(widget, popup, "idaslicer:add_seg", "Add to Slicer/")


def PLUGIN_ENTRY():
    return IDASlicerPlugin()  # ty:ignore[missing-argument]
