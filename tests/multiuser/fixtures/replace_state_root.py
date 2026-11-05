"""Synthetic child that swaps its disposable root for an external symlink."""

import json
import os
from pathlib import Path
import sys


root = Path(os.environ["HERMES_MU_STATE_ROOT"])
external = Path(sys.argv[1])
old_root = root.with_name(root.name + ".moved-by-child")
root.rename(old_root)
root.symlink_to(external, target_is_directory=True)
print(
    json.dumps(
        {"root": str(root), "moved_root": str(old_root), "external": str(external)}
    )
)
