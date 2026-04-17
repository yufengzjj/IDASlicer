# IDASlicer

IDASlicer is a productivity plugin for IDA Pro designed to help reverse engineers extract, manage, and "slice" specific parts of a binary (functions, segments, or arbitrary selections) into new IDA databases or raw binary files, especially useful for the analysis of large files.

[中文版](./README_zh.md)

## Features

- **Multi-Source Slicing**: Add entries to your slice list directly from the disassembly view via right-click context menus:
  - **Add function to slicer**: Automatically detects the current function boundaries.
  - **Add selection to slicer**: Uses your current manual highlight/selection.
  - **Add current segment to slicer**: Grabs the entire segment containing the cursor.
- **Slicer Management**: A dedicated UI panel to review, edit (name, range, permissions, etc.), or delete entries before processing.
- **Persistence**: 
  - **Per-Binary List**: Your slicer list is automatically saved and loaded based on the MD5 of the binary you are analyzing.
  - **Path Memory**: Remembers the last directory used for importing `.seg` files.
- **Database Slicing (IDA 9.1+)**:
  - Creates a brand-new IDA database (`.i64`) containing only the selected slices.
  - Automatically detects file types (ELF, PE, Mach-O) and architectures (x86, x64, ARM, ARM64) to use appropriate templates.
  - Uses the IDA Domain API for headless database generation.
- **Raw Binary Export**:
  - Export all slices as individual raw binary files.
  - Filenames are automatically formatted as `Name_StartAddr_EndAddr.seg`.
- **Segment Import (IDA 9.1+)**: 
  - Import previously exported `.seg` files into an existing database.
  - Smart handling of overlaps: choose to overwrite existing data or create new segments for gaps.

## Requirements

- **IDA Pro 9.1+**: Required for the "Slice and Create IDA Database" and "Import .seg files" features (requires `ida_domain` API).
- **Python 3**: The plugin runs on the Python environment integrated with IDA.
- **PySide6**: Included with modern IDA Pro installations.

## Installation

Copy entire folder into your IDA plugins directory:
   - **Windows**: `%AppData%\Hex-Rays\IDA Pro\plugins`
   - **Linux/macOS**: `~/.idapro/plugins`

## Usage

1. **Populate the List**:
   - Right-click in the **IDA View (Disassembly)**.
   - Navigate to `Add to Slicer /`.
   - Choose to add a function, selection, or the entire segment.
2. **Open the Plugin**:
   - Go to `Edit -> Plugins -> IDASlicer`.
3. **Review and Edit**:
   - Double-click an entry in the table to modify its properties.
   - Right-click an entry to delete it.
   - The list is automatically saved to `idaslicer_config.json`.
4. **Export / Import**:
   - **Slice and Create IDA Database**: Generates a new `.i64` file with the segments recreated and data populated.
   - **Save segments to .seg files**: Dumps the raw bytes of each entry into `.seg` files.
   - **Import .seg files**: Load `.seg` files back into the database, with conflict resolution for overlapping segments.

## How it Works

### Database Slicing
The plugin uses a template-based approach. It copies a "mini" database from the `obj_minis` directory and then runs a background Python process using IDA's `ida_domain` API to inject the selected segments and their content into the new database without closing your current session.

### Raw Export
It utilizes `ida_bytes.get_bytes` to read the database content and writes it directly to disk, ensuring that any manual patches or re-analyzed data in your current IDB are preserved in the export.

### Segment Import
Uses the `ida_domain` API to modify segments and bytes. It parses metadata from the `.seg` filename, detects overlaps with existing segments, and provides options to overwrite data or fill gaps by creating new segments.

## License
[MIT](LICENSE)
