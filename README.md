# IDASlicer

IDASlicer extracts and "slices" parts of a binary — functions, segments, or selections — into new IDA databases or `.seg` files. Handy for carving a manageable piece out of a large binary.

[中文版](./README_zh.md)

## Features

- **Add to slicer** (right-click in the disassembly → `Add to Slicer/`):
  - **Function** — adds the function (or, where IDA has not defined one, the code reachable from the cursor) and the data it references, without following calls into other functions.
  - **Selection** or **Current segment**. A range that overlaps an entry already listed is merged into it; ranges that only touch stay separate rows.
  - **Function recursively** — adds the function plus every code/data range it references, followed transitively. Ranges that touch or overlap are merged into one entry — both within the scan and against the ranges already listed, so a discovery adjacent to an existing entry extends it instead of adding a row. Real gaps are left alone, and ranges never merge across a segment boundary. Cancelling a long scan keeps what was found so far and warns that the list is incomplete.
  - **Callers (Xrefs graph to) recursively** — like *Function recursively*, but the scan starts from a whole cluster: the function at the cursor (or the data item there) plus every function that refers to it, followed up transitively, as IDA's *Xrefs graph to* shows them. A reference anywhere in a function counts, references passing through data (a function pointer table, a vtable) are followed to whatever refers to that data, and falling through into a function's start counts as a reference. Starting from a widely used function can pull in most of the program.
- **Slicer panel** (`Edit → Plugins → IDASlicer`): review, edit (name, range, permissions, type, align), or delete entries; the Size column shows each range's length, and the Ref column shows the reference that pulled the range into the list (blank for a scan seed or a hand-added range). Clicking a Start, End or Ref cell jumps the disassembly there. Editing a recursive entry's range re-scans it for new references. The list is saved next to the database as `<database>.slicer.json` — keep it with the database when you move or copy it. A list saved by an older version in `idaslicer_config.json` moves there the first time its database is opened.
- **Settings** (button in the panel): tune how far a reference into unsized data keeps gluing adjacent items together, and whether already-named data is pulled in at all. Saved globally in `idaslicer_config.json`.
- **Create IDA database (9.1+)**: builds a new `.i64` containing only the slices, auto-selecting a template by file type (ELF/PE/Mach-O) and architecture (x86/x64/ARM/ARM64). Before exporting — here and to `.seg` files — overlapping entries are merged and empty ones skipped, so no two segments share an address; the list itself is left as is. Bytes that have no value in the source (BSS, extern) get none in the slice either. If some range cannot be added, the database is still saved and the missing ranges are listed.
- **Export `.seg` files**: each entry is saved with its segment name, range, permissions, type/align, bytes, and user-defined symbol names. Optionally **merge** all ranges into a single file for easy transport.
- **Import `.seg` files (9.1+)**: load single or merged files back into a database, restoring bytes, segment attributes, and symbol names. Files are read as plain data only, so a crafted `.seg` cannot run code. Overlaps with existing segments are resolved by overwriting or by creating new segments for gaps. Imported ranges are merged into the slicer list as a whole — across all selected files and against the ranges already listed — so an import that abuts or overlaps an existing entry extends it instead of adding a second row.
- **Export / import user analysis** (buttons in the panel): saves what you added to the analysis to a JSON file, so it survives a database IDA can no longer open — rebuild the database from the binary and import the file. It holds patched bytes, user-set names (global and local), types applied to functions, data and call instructions, function comments, bookmarks, function bounds, the local types the rest of the export uses, plus the types they depend on (IDA does not record which ones you wrote; turn on *Export every local type* in Settings to keep types nothing uses yet), and the decompiler's user edits: variable names, types and comments, variable mappings, pseudocode comments, labels, number formats, union selections and call types. *Only the listed ranges* (next to the buttons) limits an export or an import to the ranges in the slicer list, functions by their start: export it to carry a database's analysis into a slice made from those ranges (such a file is not a full backup), import it so that nothing outside them is touched. Local types have no address and are imported whole. IDA's own dummy names (`sub_`, `loc_`, …) are left out, and so are comments other than function comments and operand representations (enum, struct offset, forced): IDA and its loaders write most of those, and nothing marks the ones you wrote. The same works for analysis done in a slice: a slice keeps the source's addresses and image base, so its export imports straight back into the full database — except decompiler edits in a function the slice decompiles differently (e.g. its callees lie outside the slice). Slices made by older versions kept the addresses but not the image base; import tells the two cases apart by where the exported functions land, and asks when it cannot. On import the file wins over what the database holds, addresses follow a changed image base, and a different input binary is asked about first. **Auto-export** (off by default; turn it on in Settings by choosing an interval) writes to `<database>.userdata/` next to the database, keeps the newest 10, and skips its turn when nothing changed, so an idle database costs next to nothing.

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
