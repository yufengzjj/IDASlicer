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
import ida_kernwin
import ida_nalt
import ida_segment
from PySide6 import QtCore, QtWidgets

try:
    import ida_domain
except ImportError:
    ida_domain = None

WORKER_SCRIPT = """
import sys
import pickle
import os
import traceback

def run_worker(data_path):
    try:
        import ida_domain
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
                if entry_data['content']:
                    db.bytes.set_bytes_at(entry_data['start'], entry_data['content'])

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
    def __init__(self, name, start, end, perm, seg_type, align, sig=""):
        self.name = name
        self.start = start
        self.end = end
        self.perm = perm  # rwx
        self.seg_type = seg_type
        self.align = align
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
        )

    def size(self):
        return self.end - self.start


def get_seg_class(seg_type):
    if seg_type == ida_segment.SEG_CODE:
        return "CODE"
    elif seg_type == ida_segment.SEG_BSS:
        return "BSS"
    return "DATA"


# --- UI Components ---


class SlicerTable(QtWidgets.QTableWidget):
    def __init__(self, plugin, parent=None):
        super(SlicerTable, self).__init__(parent)
        self.plugin = plugin
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels(["Name", "Start", "End", "Attributes", "Sig"])
        self.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection
        )
        self.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

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

            perm_str = ""
            perm_str += "R" if entry.perm & ida_segment.SEGPERM_READ else "."
            perm_str += "W" if entry.perm & ida_segment.SEGPERM_WRITE else "."
            perm_str += "X" if entry.perm & ida_segment.SEGPERM_EXEC else "."
            attr_str = f"{perm_str} | T:{entry.seg_type} | A:{entry.align}"
            self.setItem(i, 3, QtWidgets.QTableWidgetItem(attr_str))
            self.setItem(i, 4, QtWidgets.QTableWidgetItem(entry.sig))

    def show_context_menu(self, pos):
        selected_rows = [index.row() for index in self.selectionModel().selectedRows()]
        if not selected_rows:
            return

        menu = QtWidgets.QMenu()
        edit_action = None
        if len(selected_rows) == 1:
            edit_action = menu.addAction("Edit")
        delete_action = menu.addAction("Delete")

        action = menu.exec(self.mapToGlobal(pos))
        if edit_action and action == edit_action:
            self.edit_entry(selected_rows[0])
        elif action == delete_action:
            self.delete_entries(selected_rows)

    def delete_entries(self, rows):
        # Sort rows in reverse order to pop from the end to keep indices valid
        for row in sorted(rows, reverse=True):
            self.entries.pop(row)
        self.refresh()
        self.plugin.save_config()

    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key.Key_Delete:
            selected_rows = [
                index.row() for index in self.selectionModel().selectedRows()
            ]
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

        layout.addRow("Name:", name_edit)
        layout.addRow("Start (hex):", start_edit)
        layout.addRow("End (hex):", end_edit)
        layout.addRow("Permissions (int):", perm_edit)
        layout.addRow("Type (int):", type_edit)
        layout.addRow("Alignment (int):", align_edit)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)

        if dialog.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            try:
                entry.name = name_edit.text()
                entry.start = int(start_edit.text(), 16)
                entry.end = int(end_edit.text(), 16)
                entry.perm = int(perm_edit.text())
                entry.seg_type = int(type_edit.text())
                entry.align = int(align_edit.text())
                entry.update_sig()
                self.refresh()
                self.plugin.save_config()
            except ValueError:
                QtWidgets.QMessageBox.warning(self, "Error", "Invalid input format.")


class SlicerPluginForm(ida_kernwin.PluginForm):
    def __init__(self, plugin):
        super(SlicerPluginForm, self).__init__()
        self.plugin = plugin

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.layout = QtWidgets.QVBoxLayout(self.parent)

        self.table = SlicerTable(self.plugin)
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
            QtWidgets.QMessageBox.warning(
                self.parent, "Error", "Please enter a file type."
            )
            return

        self.plugin.perform_slice(self.table.entries, file_type_str)

    def on_save_seg_clicked(self):
        self.plugin.save_segments_to_files(self.table.entries)

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
        if self.mode == "function":
            ea = ctx.cur_ea
            func = ida_funcs.get_func(ea)
            if not func:
                print("No function at current address.")
                return 0
            start, end = func.start_ea, func.end_ea
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
                print(
                    f"No selection, adding current item at {hex(start)} (size {item_size})"
                )

        seg = ida_segment.getseg(start)
        if not seg:
            print("Address not in segment.")
            return 0

        name = ida_segment.get_segm_name(seg)
        perm = seg.perm
        seg_type = seg.type
        align = seg.align

        entry = SlicerEntry(name, start, end, perm, seg_type, align)
        self.plugin.add_to_list(entry)
        return 1

    def update(self, ctx):
        return (
            ida_kernwin.AST_ENABLE_FOR_WIDGET
            if ctx.widget_type == ida_kernwin.BWN_DISASM
            else ida_kernwin.AST_DISABLE_FOR_WIDGET
        )


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
        self.hooks = SlicerUIHooks(self)
        self.hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def _get_config_path(self):
        # Store in the same directory as the plugin
        return os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "idaslicer_config.json"
        )

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
            except:
                pass

        config["last_import_path"] = self.last_import_path

        md5 = ida_nalt.retrieve_input_file_md5()
        if md5:
            md5_hex = md5.hex()
            if "entries" not in config:
                config["entries"] = {}
            config["entries"][md5_hex] = [e.to_dict() for e in self.entries]

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
            self.form = SlicerPluginForm(self)
        self.form.Show("Slicer List")
        if self.form:
            self.form.table.refresh()

    def register_actions(self):
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "idaslicer:add_func",
                "Add function to slicer",
                AddToSlicerHandler(self, "function"),
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "idaslicer:add_sel",
                "Add selection to slicer",
                AddToSlicerHandler(self, "selection"),
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "idaslicer:add_seg",
                "Add current segment to slicer",
                AddToSlicerHandler(self, "segment"),
            )
        )

    def unregister_actions(self):
        ida_kernwin.unregister_action("idaslicer:add_func")
        ida_kernwin.unregister_action("idaslicer:add_sel")
        ida_kernwin.unregister_action("idaslicer:add_seg")

    def add_to_list(self, entry):
        self.entries.append(entry)
        self.save_config()
        if self.form:
            self.form.table.refresh()

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
            QtWidgets.QMessageBox.warning(
                None, "Error", f"Template not found:\n{template_path}"
            )
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
            QtWidgets.QMessageBox.critical(
                None, "Error", f"Failed to copy template:\n{e}"
            )
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
                    "seg_class": seg_class,
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
                QtWidgets.QMessageBox.information(
                    None, "Success", f"File saved to:\n{out_path}"
                )
            else:
                error_msg = result.stderr or result.stdout
                print(f"Subprocess failed:\n{error_msg}")
                QtWidgets.QMessageBox.critical(
                    None, "Error", f"Subprocess failed:\n{error_msg}"
                )
        except Exception as e:
            print(f"Error during subprocess orchestration: {e}")
            QtWidgets.QMessageBox.critical(
                None, "Error", f"Error during subprocess orchestration:\n{e}"
            )
        finally:
            if os.path.exists(data_path):
                os.remove(data_path)
            if os.path.exists(script_path):
                os.remove(script_path)

    def save_segments_to_files(self, entries: list[SlicerEntry]):
        if not entries:
            print("No entries to save.")
            return

        input_path = ida_nalt.get_input_file_path()
        if not input_path:
            print("Could not determine input file path.")
            return

        out_dir = os.path.dirname(input_path)

        count = 0
        for entry in entries:
            size = entry.size()
            if size <= 0:
                continue

            content = ida_bytes.get_bytes(entry.start, size)
            if content is None:
                print(f"Failed to read bytes at {hex(entry.start)}")
                continue

            # Update sig to reflect current memory state
            entry.update_sig()

            # Format: {name}_{start}_{end}_{perm}_{seg_class}_{sig}.seg
            filename = f"{entry.name}_{hex(entry.start)}_{hex(entry.end)}_{hex(entry.perm)}_{get_seg_class(entry.seg_type)}_{entry.sig}.seg"
            # Sanitize filename
            filename = "".join([c for c in filename if c not in '<>:"/\\|?*'])
            file_path = os.path.join(out_dir, filename)

            try:
                with open(file_path, "wb") as f:
                    f.write(content)
                count += 1
            except Exception as e:
                print(f"Failed to write file {file_path}: {e}")

        QtWidgets.QMessageBox.information(
            None, "Success", f"Successfully saved {count} segment files to:\n{out_dir}"
        )

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

            for file_path in files:
                filename = os.path.basename(file_path)
                if not filename.endswith(".seg"):
                    continue

                # Parse: {name}_{start}_{end}_{perm}_{seg_class}_{sig}.seg
                parts = filename[:-4].split("_")
                if len(parts) < 6:
                    print(f"Skipping invalid filename (too few parts): {filename}")
                    continue

                expected_sig = parts[-1]
                seg_class = parts[-2]
                try:
                    perm = int(parts[-3], 16)
                    end = int(parts[-4], 16)
                    start = int(parts[-5], 16)
                except ValueError:
                    print(f"Skipping invalid hex values in filename: {filename}")
                    continue

                name = "_".join(parts[:-5])

                try:
                    with open(file_path, "rb") as f:
                        content = f.read()
                except Exception as e:
                    print(f"Failed to read {file_path}: {e}")
                    continue

                # MD5 Validation
                actual_sig = hashlib.md5(content).hexdigest()
                if actual_sig != expected_sig:
                    msg = f"MD5 mismatch for {filename}!\n\nExpected: {expected_sig}\nActual: {actual_sig}\n\nDo you want to skip this file?"
                    res = QtWidgets.QMessageBox.question(
                        None,
                        "Validation Error",
                        msg,
                        QtWidgets.QMessageBox.StandardButton.Yes
                        | QtWidgets.QMessageBox.StandardButton.No,
                        QtWidgets.QMessageBox.StandardButton.Yes,
                    )
                    if res == QtWidgets.QMessageBox.StandardButton.Yes:
                        continue

                if len(content) != (end - start):
                    print(f"Content size mismatch for {filename}")

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
                            f"The segment from '{filename}' overlaps with existing segment '{db.segments.get_name(s)}' at {hex(o_start)}-{hex(o_end)}.\n\nDo you want to overwrite the data?"
                        )
                        msg_box.setStandardButtons(
                            QtWidgets.QMessageBox.StandardButton.Yes
                            | QtWidgets.QMessageBox.StandardButton.No
                        )
                        msg_box.setDefaultButton(
                            QtWidgets.QMessageBox.StandardButton.No
                        )

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
                    results.append(
                        f"Overwrote part of '{db.segments.get_name(s)}' at {hex(o_start)}-{hex(o_end)}"
                    )

                # 2. Create segments for gaps
                current_pos = start
                for s in overlaps:
                    if current_pos < s.start_ea:
                        unique_name = get_unique_name(name, existing_names)
                        new_seg = db.segments.add(
                            0, current_pos, s.start_ea, unique_name, seg_class
                        )
                        if new_seg:
                            db.segments.set_permissions(new_seg, perm)
                            offset = current_pos - start
                            chunk = content[
                                offset : offset + (s.start_ea - current_pos)
                            ]
                            db.bytes.set_bytes_at(current_pos, chunk)
                            results.append(
                                f"Created segment '{unique_name}' at {hex(current_pos)}-{hex(s.start_ea)}"
                            )
                            existing_names.append(unique_name)
                    current_pos = max(current_pos, s.end_ea)

                if current_pos < end:
                    unique_name = get_unique_name(name, existing_names)
                    new_seg = db.segments.add(
                        0, current_pos, end, unique_name, seg_class
                    )
                    if new_seg:
                        db.segments.set_permissions(new_seg, perm)
                        offset = current_pos - start
                        chunk = content[offset : offset + (end - current_pos)]
                        db.bytes.set_bytes_at(current_pos, chunk)
                        results.append(
                            f"Created segment '{unique_name}' at {hex(current_pos)}-{hex(end)}"
                        )
                        existing_names.append(unique_name)

        summary = "\n".join(results) if results else "No changes made."
        QtWidgets.QMessageBox.information(None, "Import Summary", summary)


class SlicerUIHooks(ida_kernwin.UI_Hooks):
    def __init__(self, plugin):
        super(SlicerUIHooks, self).__init__()
        self.plugin = plugin

    def finish_populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(
                widget, popup, "idaslicer:add_func", "Add to Slicer/"
            )
            ida_kernwin.attach_action_to_popup(
                widget, popup, "idaslicer:add_sel", "Add to Slicer/"
            )
            ida_kernwin.attach_action_to_popup(
                widget, popup, "idaslicer:add_seg", "Add to Slicer/"
            )


def PLUGIN_ENTRY():
    return IDASlicerPlugin()
