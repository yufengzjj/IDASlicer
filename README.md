# IDASlicer

IDASlicer extracts and "slices" parts of a binary — functions, segments, or selections — into new IDA databases or `.seg` files. Handy for carving a manageable piece out of a large binary.

[中文版](./README_zh.md)

## Features

- **Add to slicer** (right-click in the disassembly → `Add to Slicer/`):
  - **Function** — adds the function (or, where IDA has not defined one, the code reachable from the cursor) and the data it references, without following calls into other functions.
  - **Selection** or **Current segment**. A range that overlaps an entry already listed is merged into it; ranges that only touch stay separate rows.
  - **Function recursively** — adds the function plus every code/data range it references, followed transitively. Ranges that touch or overlap are merged into one entry — both within the scan and against the ranges already listed, so a discovery adjacent to an existing entry extends it instead of adding a row. Real gaps are left alone, and ranges never merge across a segment boundary. Cancelling a long scan keeps what was found so far and warns that the list is incomplete.
- **Slicer panel** (`Edit → Plugins → IDASlicer`): review, edit (name, range, permissions, type, align), or delete entries; the Size column shows each range's length, and the Ref column shows the reference that pulled the range into the list (blank for a scan seed or a hand-added range). Clicking a Start, End or Ref cell jumps the disassembly there. Editing a recursive entry's range re-scans it for new references. The list is saved per-binary (keyed by input MD5) in `idaslicer_config.json`.
- **Settings** (button in the panel): tune how far a reference into unsized data keeps gluing adjacent items together, and whether already-named data is pulled in at all. Saved globally in `idaslicer_config.json`.
- **Create IDA database (9.1+)**: builds a new `.i64` containing only the slices, auto-selecting a template by file type (ELF/PE/Mach-O) and architecture (x86/x64/ARM/ARM64). Before exporting — here and to `.seg` files — overlapping entries are merged and empty ones skipped, so no two segments share an address; the list itself is left as is. Bytes that have no value in the source (BSS, extern) get none in the slice either. If some range cannot be added, the database is still saved and the missing ranges are listed.
- **Export `.seg` files**: each entry is saved with its segment name, range, permissions, type/align, bytes, and user-defined symbol names. Optionally **merge** all ranges into a single file for easy transport.
- **Import `.seg` files (9.1+)**: load single or merged files back into a database, restoring bytes, segment attributes, and symbol names. Files are read as plain data only, so a crafted `.seg` cannot run code. Overlaps with existing segments are resolved by overwriting or by creating new segments for gaps. Imported ranges are merged into the slicer list as a whole — across all selected files and against the ranges already listed — so an import that abuts or overlaps an existing entry extends it instead of adding a second row.

## Requirements

- **IDA Pro 9.1+** for the database create/import features (uses the `ida_domain` API). The other features work on earlier 9.x.
- **PySide6** (bundled with modern IDA Pro).

## Installation

Copy the whole folder into your IDA plugins directory:
- **Windows**: `%AppData%\Hex-Rays\IDA Pro\plugins`
- **Linux/macOS**: `~/.idapro/plugins`

## How it works

- **Database slicing** copies a mini template from `obj_minis/` and runs a background process via the `ida_domain` API to recreate the segments, bytes, attributes, and names — without closing your current session.
- **`.seg` files** are pickled dicts holding the metadata, bytes, and collected symbol names, so nothing depends on fragile filename parsing. Import auto-detects single vs. merged files and reapplies everything (names via `ida_name`, type/align on the created segment), with overlap conflict resolution.

## License
[MIT](LICENSE)
