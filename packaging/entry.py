"""Frozen-exe entry point.

PyInstaller runs the entry script as top-level `__main__` with NO package context,
so a relative import (`from .cli import ...`) fails. This launcher lives OUTSIDE the
package and uses an absolute import, which resolves both during analysis (via pathex)
and at runtime (the whole `redness` package is bundled).

`python -m redness` keeps using `redness/__main__.py` (relative import is correct there).
"""
import sys

from redness.cli import main

if __name__ == "__main__":
    sys.exit(main())
