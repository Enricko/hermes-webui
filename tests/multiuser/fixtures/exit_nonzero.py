"""Synthetic failing child for verifying launcher teardown on failure."""

import os


print(os.environ["HERMES_MU_STATE_ROOT"])
raise SystemExit(17)
