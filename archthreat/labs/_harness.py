"""Lets every lab test run against YOUR starter file (default) or the reference solution.

pytest labs/lab01_sarif                 # tests your code in starter.py
LAB_SOLUTION=1 pytest labs/lab01_sarif  # tests the reference implementation in src/
"""

import importlib
import os
from types import ModuleType


def load(starter: str, solution: str) -> ModuleType:
    target = solution if os.environ.get("LAB_SOLUTION") == "1" else starter
    return importlib.import_module(target)
