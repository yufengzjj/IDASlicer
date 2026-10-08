import sys
import types


def install(known: dict):
    """idalib's PySide6 refuses to import outside the GUI. The scanner and the
    export/import paths need only the classes in `known`; any other name
    becomes an empty class, which is enough for the module-level UI classes to
    be defined."""
    cache = {}

    def lookup(name):
        if name.startswith("__"):
            raise AttributeError(name)
        if name in known:
            return known[name]
        return cache.setdefault(name, type(name, (), {}))

    pkg = types.ModuleType("PySide6")
    widgets = types.ModuleType("PySide6.QtWidgets")
    core = types.ModuleType("PySide6.QtCore")
    widgets.__getattr__ = lookup
    core.__getattr__ = lookup
    pkg.QtWidgets, pkg.QtCore = widgets, core
    sys.modules.update({"PySide6": pkg, "PySide6.QtWidgets": widgets, "PySide6.QtCore": core})
