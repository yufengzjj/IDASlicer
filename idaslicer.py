import hashlib
import json
import os
import pickle
import shutil
import subprocess
import sys
import tempfile

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


class SlicerEntry:
    def __init__(self, name, start, end, perm, seg_type, align, sig="", recursive=False):
        self.name = name
        self.start = start
        self.end = end
        self.perm = perm  # rwx
        self.seg_type = seg_type
        self.align = align
        # True if this range was discovered by a recursive reference scan. Such
        # entries are re-scanned when their range is edited.
        self.recursive = recursive
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
        )

    def size(self):
        return self.end - self.start


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


def get_loose_data_range(ea, max_explore_len=0):
    end_ea = ea
    while True:
        if end_ea == idaapi.BADADDR or not ida_bytes.is_mapped(end_ea):
            break
        name = ida_name.get_name(end_ea)
        if end_ea != ea and name:
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
):
    """check the possible func range(or just a commom code chunk)"""
    func = ida_funcs.get_func(ref)
    if func and func.start_ea != cur_func.start_ea:
        if ref == func.start_ea:
            if funcs_to_export is not None:
                funcs_to_export.extend(get_recursive_functions(func.start_ea))
        else:
            if func.start_ea <= ref < func.end_ea:
                r = ida_range.range_t(ref, func.end_ea)
                if not _is_range_covered(processed_ranges, s, e):
                    ranges.append(r)
            else:
                for s, e in reconstruct_func_range(ref):
                    r = ida_range.range_t(s, e)
                    if not _is_range_covered(processed_ranges, s, e):
                        ranges.append(r)
    elif not func:
        for s, e in reconstruct_func_range(ref):
            r = ida_range.range_t(s, e)
            if not _is_range_covered(processed_ranges, s, e):
                ranges.append(r)


def check_c_ref_range(
    ranges: list[ida_range.range_t],
    addr: int,
    cur_range: tuple[int, int],
    cur_func: ida_funcs.func_t,
    funcs_to_export: list[int] | None,
    processed_ranges: set[tuple[int, int]],
):
    """check code ref at addr"""
    for ref in idautils.XrefsFrom(addr, ida_xref.XREF_FAR):
        if cur_range[0] <= ref.to < cur_range[1]:
            continue
        if ref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
            if funcs_to_export is not None:
                funcs_to_export.append(ref.to)
            continue
        check_func_range(ranges, ref.to, cur_func, funcs_to_export, processed_ranges)


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
    skip_named_data: bool = False,
    max_explore_len: int = 128,
):
    """check code opraand ref in cur_range"""
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
                funcs_to_export.append(o_ref)
        elif ida_bytes.is_data(o_flags):
            if skip_named_data and ida_bytes.has_name(o_flags):
                continue
            r = ida_range.range_t(o_ref, o_ref + ida_bytes.get_item_size(o_ref))
            if not _is_range_covered(processed_ranges, r.start_ea, r.end_ea):
                ranges.append(r)
        else:
            if skip_named_data and ida_bytes.has_name(o_flags):
                continue
            r = get_loose_data_range(o_ref, max_explore_len)
            if not _is_range_covered(processed_ranges, r.start_ea, r.end_ea):
                ranges.append(r)


def check_d_ref_range(
    ranges: list[ida_range.range_t],
    cur_range: tuple[int, int],
    cur_func: ida_funcs.func_t,
    funcs_to_export: list[int] | None,
    processed_ranges: set[tuple[int, int]],
    skip_named_data: bool = False,
    max_explore_len: int = 128,
):
    """check data ref"""
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
                    if ida_bytes.is_code(flags):
                        if funcs_to_export is not None:
                            funcs_to_export.append(ptr)
                    elif not (skip_named_data and ida_bytes.has_name(flags)):
                        r = get_loose_data_range(ptr, max_explore_len)
                        if not _is_range_covered(processed_ranges, r.start_ea, r.end_ea):
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


def get_recursive_functions(start_ea) -> list[int]:
    """Get all functions reachable from start_ea. Library functions and named
    import thunks are included in the result but NOT recursed into; only their
    first instruction is later collected so references to them show the name."""
    to_export = list()
    stack = [start_ea]

    while stack:
        ea = stack.pop(0)
        func = ida_funcs.get_func(ea) or _NoFunc(ea)
        if not func:
            continue

        func_ea = func.start_ea
        if func_ea in to_export:
            continue

        to_export.append(func_ea)

        # Don't recurse into library functions / import stubs.
        if is_stub_func(func):
            continue

        # Find all calls from this function
        for head in idautils.FuncItems(func_ea):
            for ref in idautils.XrefsFrom(head, ida_xref.XREF_FAR):
                called_func = ida_funcs.get_func(ref.to)
                if called_func and called_func.start_ea != func_ea:
                    stack.append(called_func.start_ea)
                elif not called_func and ref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
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
):
    """Drain a worklist of ranges, recording each into `collected` and appending
    newly discovered code/data ranges (back onto `all_ranges`) and referenced
    functions (onto `funcs_to_export`). `cur_func` is the function the seed
    ranges belong to (or `_NO_FUNC` for loose ranges)."""
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
                check_c_ref_range(all_ranges, ida_bytes.prev_head(end, start), (start, end), cur_func, funcs_to_export, processed_ranges)
            else:
                for head in idautils.Heads(start, end):
                    check_c_ref_range(all_ranges, head, (start, end), cur_func, funcs_to_export, processed_ranges)
            check_o_ref_range(all_ranges, (start, end), cur_func, funcs_to_export, processed_ranges)
        else:
            check_d_ref_range(all_ranges, (start, end), cur_func, funcs_to_export, processed_ranges)

        processed_ranges.add((start, end))


def _scan_func_ranges(func, collected: list, funcs_to_export: list, processed_ranges: set):
    """Scan a single function's ranges via the shared worklist driver."""
    ranges = ida_range.rangeset_t()  # ty:ignore[missing-argument]
    if func.end_ea == idaapi.BADADDR:
        all_ranges = [ida_range.range_t(s, e) for (s, e) in reconstruct_func_range(func.start_ea)]
    else:
        ida_funcs.get_func_ranges(ranges, func)
        all_ranges = [ranges.getrange(i) for i in range(ranges.nranges())]
    all_ranges.sort(key=lambda r: (0 if r.start_ea == func.start_ea else 1, r.start_ea))
    _scan_worklist(all_ranges, func, collected, funcs_to_export, processed_ranges)


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


def _drain_functions(funcs_to_export: list, collected: list, processed_ranges: set):
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
        if is_stub_func(func):
            _collect_stub_range(func, collected, processed_ranges)
        else:
            _scan_func_ranges(func, collected, funcs_to_export, processed_ranges)


def collect_recursive_ranges(start_ea) -> list:
    """Collect the range of the function at `start_ea` plus all code/data ranges
    it references, recursively following the discovered functions/ranges.

    Returns a list of (start_ea, end_ea) tuples."""
    funcs_to_export = get_recursive_functions(start_ea)
    processed_ranges = set()
    collected = []
    _drain_functions(funcs_to_export, collected, processed_ranges)
    return collected


def collect_recursive_ranges_from_range(start, end) -> list:
    """Like `collect_recursive_ranges`, but seeded from an arbitrary range
    instead of a function. Used when an existing range is edited: the new range
    is scanned for references and everything reachable is collected.

    The seed range itself is included in the result."""
    processed_ranges = set()
    funcs_to_export = []
    collected = []
    cur_func = ida_funcs.get_func(start) or _NO_FUNC
    _scan_worklist(
        [ida_range.range_t(start, end)],
        cur_func,
        collected,
        funcs_to_export,
        processed_ranges,
    )
    _drain_functions(funcs_to_export, collected, processed_ranges)
    return collected


def collect_recursive_ranges_from_ranges(seed_ranges) -> list:
    """Like `collect_recursive_ranges_from_range`, but seeded from several loose
    ranges at once (e.g. the blocks returned by `reconstruct_func_range` for a
    function IDA never defined). The seeds are treated as not belonging to any
    function (`_NO_FUNC`); each is scanned for references and everything
    reachable is collected. The seed ranges themselves are included."""
    processed_ranges = set()
    funcs_to_export = []
    collected = []
    seeds = [ida_range.range_t(s, e) for s, e in seed_ranges if s < e]
    _scan_worklist(seeds, _NO_FUNC, collected, funcs_to_export, processed_ranges)
    _drain_functions(funcs_to_export, collected, processed_ranges)
    return collected


# --- UI Components ---


class SlicerTable(QtWidgets.QTableWidget):
    def __init__(self, plugin, parent=None):
        super(SlicerTable, self).__init__(parent)
        self.plugin = plugin
        self._filter_text = ""
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels(["Name", "Start", "End", "Size", "Attributes", "Sig"])
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
        self.cellClicked.connect(self.on_cell_clicked)

    @property
    def entries(self):
        return self.plugin.entries

    def add_entry(self, entry):
        self.entries.append(entry)
        self.refresh()
        self.plugin.save_config()

    def refresh(self):
        self.setRowCount(0)
        for i, entry in enumerate(self.entries):
            self.insertRow(i)
            self.setItem(i, 0, QtWidgets.QTableWidgetItem(entry.name))
            self.setItem(i, 1, QtWidgets.QTableWidgetItem(hex(entry.start)))
            self.setItem(i, 2, QtWidgets.QTableWidgetItem(hex(entry.end)))

            size = entry.size()
            self.setItem(i, 3, QtWidgets.QTableWidgetItem(f"{hex(size)} ({size})"))

            perm_str = ""
            perm_str += "R" if entry.perm & ida_segment.SEGPERM_READ else "."
            perm_str += "W" if entry.perm & ida_segment.SEGPERM_WRITE else "."
            perm_str += "X" if entry.perm & ida_segment.SEGPERM_EXEC else "."
            attr_str = f"{perm_str} | T:{entry.seg_type} | A:{entry.align}"
            if entry.recursive:
                attr_str += " | rec"
            self.setItem(i, 4, QtWidgets.QTableWidgetItem(attr_str))
            self.setItem(i, 5, QtWidgets.QTableWidgetItem(entry.sig))
        self.apply_filter(self._filter_text)

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
        """Clicking the Start or End cell jumps the IDA view to that address."""
        if col not in (1, 2):
            return
        item = self.item(row, col)
        if item is None:
            return
        try:
            ea = int(item.text(), 16)
        except ValueError:
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
        perm_edit = QtWidgets.QLineEdit(str(entry.perm))
        type_edit = QtWidgets.QLineEdit(str(entry.seg_type))
        align_edit = QtWidgets.QLineEdit(str(entry.align))
        recursive_check = QtWidgets.QCheckBox("Re-scan references when the range changes")
        recursive_check.setChecked(entry.recursive)

        layout.addRow("Name:", name_edit)
        layout.addRow("Start (hex):", start_edit)
        layout.addRow("End (hex):", end_edit)
        layout.addRow("Permissions (int):", perm_edit)
        layout.addRow("Type (int):", type_edit)
        layout.addRow("Alignment (int):", align_edit)
        layout.addRow("Recursive:", recursive_check)

        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Ok | QtWidgets.QDialogButtonBox.StandardButton.Cancel)
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
            if func:
                funcs_to_export = [func.start_ea]
                processed_ranges = set()
                _drain_functions(funcs_to_export, blocks, processed_ranges)
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
                self.plugin.add_to_list(SlicerEntry(self.plugin._range_name(s, bseg), s, e, bseg.perm, bseg.type, bseg.align))
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
        config = {"entries": {}, "last_import_path": self.last_import_path}

        # Load existing config to preserve other MD5s
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    config = json.load(f)
            except:  # noqa: E722
                pass

        config["last_import_path"] = self.last_import_path

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
    def _apply_seg_attrs(seg_start, seg_type, align):
        """Apply numeric segment type and alignment to a freshly created segment.
        No-op when these were not recorded in the payload (None)."""
        if seg_type is None and align is None:
            return
        s = ida_segment.getseg(seg_start)
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

    def _add_collected_ranges(self, ranges):
        """Turn collected (start, end) ranges into recursive SlicerEntries,
        dropping exact duplicates and ranges fully contained in an existing
        entry or in a larger range from this same batch. Returns the count
        added (does not save/refresh — the caller does)."""
        existing = [(e.start, e.end) for e in self.entries]
        existing_set = set(existing)

        def _contained(s, e, others):
            for cs, ce in others:
                if cs <= s and e <= ce and (cs, ce) != (s, e):
                    return True
            return False

        # Process largest ranges first so that a range fully contained in a
        # bigger one (already present, or kept earlier in this pass) is dropped,
        # avoiding redundant overlapping segments / overwrite prompts on import.
        ordered = sorted(
            {(s, e) for s, e in ranges if s < e},
            key=lambda r: r[1] - r[0],
            reverse=True,
        )

        kept = []
        for start, end in ordered:
            if (start, end) in existing_set:
                continue
            if _contained(start, end, existing) or _contained(start, end, kept):
                continue
            kept.append((start, end))

        added = 0
        for start, end in kept:
            seg = ida_segment.getseg(start)
            if not seg:
                continue
            name = self._range_name(start, seg)
            entry = SlicerEntry(name, start, end, seg.perm, seg.type, seg.align, recursive=True)
            self.entries.append(entry)
            added += 1
        return added

    def add_function_recursive(self, start_ea: int):
        """Add the function at start_ea and every code/data range it references
        (recursively) to the slicer list."""
        ida_kernwin.show_wait_box("Scanning recursive references...")
        try:
            ranges = collect_recursive_ranges(start_ea)
        except Exception as e:
            ida_kernwin.hide_wait_box()
            print(f"[IDASlicer] Recursive scan failed: {e}")
            QtWidgets.QMessageBox.critical(None, "Error", f"Recursive scan failed:\n{e}")
            return
        finally:
            ida_kernwin.hide_wait_box()

        added = self._add_collected_ranges(ranges)
        self.save_config()
        if self.form:
            self.form.table.refresh()

        print(f"[IDASlicer] Recursive scan of {hex(start_ea)}: {len(ranges)} ranges found, {added} added to slicer list.")
        ida_kernwin.info(f"Added {added} ranges to the slicer list.")

    def add_ranges_recursive(self, seed_ranges):
        """Like `add_function_recursive`, but seeded from reconstructed ranges
        instead of an IDA-defined function. Used when IDA has not turned the
        code into a function (see `reconstruct_func_range`)."""
        ida_kernwin.show_wait_box("Scanning recursive references...")
        try:
            ranges = collect_recursive_ranges_from_ranges(seed_ranges)
        except Exception as e:
            ida_kernwin.hide_wait_box()
            print(f"[IDASlicer] Recursive scan failed: {e}")
            QtWidgets.QMessageBox.critical(None, "Error", f"Recursive scan failed:\n{e}")
            return
        finally:
            ida_kernwin.hide_wait_box()

        added = self._add_collected_ranges(ranges)
        self.save_config()
        if self.form:
            self.form.table.refresh()

        seeds = ", ".join(hex(s) for s, _ in seed_ranges) or "(none)"
        print(f"[IDASlicer] Recursive scan of [{seeds}]: {len(ranges)} ranges found, {added} added to slicer list.")
        ida_kernwin.info(f"Added {added} ranges to the slicer list.")

    def rescan_range_entry(self, entry):
        """Re-scan an edited recursive entry's range for references and add any
        newly discovered ranges to the slicer list."""
        ida_kernwin.show_wait_box("Re-scanning edited range...")
        try:
            ranges = collect_recursive_ranges_from_range(entry.start, entry.end)
        except Exception as e:
            ida_kernwin.hide_wait_box()
            print(f"[IDASlicer] Re-scan failed: {e}")
            QtWidgets.QMessageBox.critical(None, "Error", f"Re-scan failed:\n{e}")
            return
        finally:
            ida_kernwin.hide_wait_box()

        added = self._add_collected_ranges(ranges)
        self.save_config()
        if self.form:
            self.form.table.refresh()

        print(f"[IDASlicer] Re-scan of {hex(entry.start)}-{hex(entry.end)}: {len(ranges)} ranges found, {added} new added to slicer list.")
        if added:
            ida_kernwin.info(f"Added {added} new ranges from the re-scan.")

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
        with ida_domain.Database.open(save_on_close=False) as db:
            existing_names = [s.name for s in db.segments]

            def get_unique_name(base_name, current_names):
                if base_name not in current_names:
                    return base_name
                counter = 0
                while f"{base_name}{counter}" in current_names:
                    counter += 1
                return f"{base_name}{counter}"

            required_keys = {"start", "end", "perm", "seg_class", "content"}

            def process_payload(payload, src):
                """Import one range payload. Merging changes nothing here: a
                merged file just yields several payloads, each handled exactly
                like a standalone single-range file."""
                nonlocal overwrite_all
                if not isinstance(payload, dict) or not required_keys.issubset(payload):
                    print(f"Skipping invalid segment in {src}")
                    return

                name = payload.get("name", "")
                start = payload["start"]
                end = payload["end"]
                perm = payload["perm"]
                seg_type = payload.get("seg_type")
                align = payload.get("align")
                seg_class = payload["seg_class"]
                content = payload["content"]
                expected_sig = payload.get("sig")

                # Strip the original "_{start}" suffix so each created segment can
                # be (re)named "{base}_{its own start}". A single imported range
                # may be split into several segments around existing ones, and
                # naming each by its actual start keeps them unique/identifiable.
                addr_suffix = f"_{hex(start)}"
                base_name = name[: -len(addr_suffix)] if name.endswith(addr_suffix) else name

                # MD5 Validation
                actual_sig = hashlib.md5(content).hexdigest()
                if expected_sig and actual_sig != expected_sig:
                    msg = f"MD5 mismatch for {base_name or src}!\n\nExpected: {expected_sig}\nActual: {actual_sig}\n\nDo you want to skip this range?"
                    res = QtWidgets.QMessageBox.question(
                        None,
                        "Validation Error",
                        msg,
                        QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
                        QtWidgets.QMessageBox.StandardButton.Yes,
                    )
                    if res == QtWidgets.QMessageBox.StandardButton.Yes:
                        return

                if len(content) != (end - start):
                    print(f"Content size mismatch for {base_name or src}")

                # Find all overlapping segments
                overlaps = []
                for s in db.segments:
                    o_start = max(s.start_ea, start)
                    o_end = min(s.end_ea, end)
                    if o_start < o_end:
                        overlaps.append(s)

                overlaps.sort(key=lambda s: s.start_ea)

                # 1. Overwrite overlapping parts
                for s in overlaps:
                    o_start = max(s.start_ea, start)
                    o_end = min(s.end_ea, end)

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
                    results.append(f"Overwrote part of '{db.segments.get_name(s)}' at {hex(o_start)}-{hex(o_end)}")

                # 2. Create segments for gaps
                current_pos = start
                for s in overlaps:
                    if current_pos < s.start_ea:
                        unique_name = get_unique_name(f"{base_name}_{hex(current_pos)}", existing_names)
                        new_seg = db.segments.add(0, current_pos, s.start_ea, unique_name, seg_class)
                        if new_seg:
                            db.segments.set_permissions(new_seg, perm)
                            self._apply_seg_attrs(current_pos, seg_type, align)
                            offset = current_pos - start
                            chunk = content[offset : offset + (s.start_ea - current_pos)]
                            db.bytes.set_bytes_at(current_pos, chunk)
                            results.append(f"Created segment '{unique_name}' at {hex(current_pos)}-{hex(s.start_ea)}")
                            existing_names.append(unique_name)
                    current_pos = max(current_pos, s.end_ea)

                if current_pos < end:
                    unique_name = get_unique_name(f"{base_name}_{hex(current_pos)}", existing_names)
                    new_seg = db.segments.add(0, current_pos, end, unique_name, seg_class)
                    if new_seg:
                        db.segments.set_permissions(new_seg, perm)
                        self._apply_seg_attrs(current_pos, seg_type, align)
                        offset = current_pos - start
                        chunk = content[offset : offset + (end - current_pos)]
                        db.bytes.set_bytes_at(current_pos, chunk)
                        results.append(f"Created segment '{unique_name}' at {hex(current_pos)}-{hex(end)}")
                        existing_names.append(unique_name)

                # 3. Restore names collected from the source database.
                for off, nm in payload.get("names", []):
                    ida_name.set_name(start + off, nm, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)

                # 4. Surface the imported range in the slicer list so the user
                # can see what was brought in. The content is already written to
                # the database above, so the entry's signature matches.
                if (start, end) not in existing_ranges:
                    existing_ranges.add((start, end))
                    imported_entries.append(
                        SlicerEntry(
                            base_name or f"imported_{hex(start)}",
                            start,
                            end,
                            perm,
                            seg_type if seg_type is not None else 0,
                            align if align is not None else 0,
                        )
                    )

            for file_path in files:
                filename = os.path.basename(file_path)

                try:
                    with open(file_path, "rb") as f:
                        data = pickle.load(f)
                except Exception as e:
                    print(f"Failed to read {filename}: {e}")
                    continue

                # A merged file is a wrapper dict carrying a list of payloads; a
                # single-range file is the payload dict itself.
                if isinstance(data, dict) and isinstance(data.get("entries"), list):
                    for payload in data["entries"]:
                        process_payload(payload, filename)
                else:
                    process_payload(data, filename)

        if imported_entries:
            self.entries.extend(imported_entries)
            self.save_config()
            if self.form:
                self.form.table.refresh()

        summary = "\n".join(results) if results else "No changes made."
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
