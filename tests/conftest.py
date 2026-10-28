"""
==============================================================================
Module Name:   conftest.py
Description:   Fixtures shared by several test modules.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-27
Version:       1.0.0
License:       MIT
==============================================================================
"""

# ``env`` (two fake seed routers in two areas, a temp state directory, no Graphviz needed) is defined in
# test_multi_seed.py; re-exported here so the --area, --serve and poll-lock tests can run the real pipeline too.
from tests.test_multi_seed import env  # noqa: F401
