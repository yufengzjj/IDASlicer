# IDASlicer

IDASlicer extracts and "slices" parts of a binary — functions, segments, or selections — into new IDA databases or `.seg` files. Handy for carving a manageable piece out of a large binary.

[中文版](./README_zh.md)

## Features

- **Add to slicer** (right-click in the disassembly → `Add to Slicer/`):
  - **Function**, **Selection**, or **Current segment**.
  - **Function recursively** — adds the function plus every code/data range it references, followed transitively. Referenced library functions and import thunks contribute just their first instruction, so calls to them resolve to a name instead of an unknown address.
- **Slicer panel** (`Edit → Plugins → IDASlicer`): review, edit (name, range, permissions, type, align), or delete entries; the Size column shows each range's length. Editing a recursive entry's range re-scans it for new references. The list is saved per-binary (keyed by input MD5) in `idaslicer_config.json`.
- **Create IDA database (9.1+)**: builds a new `.i64` containing only the slices, auto-selecting a template by file type (ELF/PE/Mach-O) and architecture (x86/x64/ARM/ARM64).
- **Export `.seg` files**: each entry is saved with its segment name, range, permissions, type/align, bytes, and user-defined symbol names. Optionally **merge** all ranges into a single file for easy transport.
- **Import `.seg` files (9.1+)**: load single or merged files back into a database, restoring bytes, segment attributes, and symbol names. Overlaps with existing segments are resolved by overwriting or by creating new segments for gaps.

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
