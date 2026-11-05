"""Synthetic skipped test to ensure an unperformed tier cannot report PASS."""

import pytest


def test_explicitly_skipped_is_not_a_pass():
    pytest.skip("synthetic mandatory check was not run")
