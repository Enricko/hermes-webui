"""Synthetic script that attempts an import from its original repo sibling."""

import os
import sys

os.environ["F02_SYNTHETIC_IMPORT_MARKER"] = sys.argv[1]
import import_closure_dependency  # noqa: F401,E402
