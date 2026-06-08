from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


_ORIGINAL_PATH = Path(__file__).with_name("graph_service.py")
_SPEC = importlib.util.spec_from_file_location("_adbygod_original_graph_service", _ORIGINAL_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError(f"Cannot load original graph service from {_ORIGINAL_PATH}")
_original = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("_adbygod_original_graph_service", _original)
_SPEC.loader.exec_module(_original)

_original.EDGE_RISK.update({
    "WRITE_SPN": 0.80,
    "ADD_KEY_CREDENTIAL_LINK": 0.90,
    "WRITE_GP_LINK": 0.84,
    "WRITE_ACCOUNT_RESTRICTIONS": 0.82,
    "HAS_SESSION": 0.55,
    "MANAGE_CA": 0.92,
    "MANAGE_CERTIFICATES": 0.88,
    "CA_PRIVATE_KEY_CONTROL": 1.00,
    "GOLDEN_CERT": 1.00,
})
_original.CONTROL_EDGES.update({
    "READ_LAPS_PASSWORD", "READ_GMSA_PASSWORD", "WRITE_SPN",
    "ADD_KEY_CREDENTIAL_LINK", "WRITE_GP_LINK", "WRITE_ACCOUNT_RESTRICTIONS",
    "SQL_ADMIN", "MANAGE_CA", "MANAGE_CERTIFICATES",
    "CA_PRIVATE_KEY_CONTROL", "GOLDEN_CERT",
})
_original.CREDENTIAL_EDGES.update({
    "READ_LAPS_PASSWORD", "READ_GMSA_PASSWORD", "ADD_KEY_CREDENTIAL_LINK",
    "CA_PRIVATE_KEY_CONTROL", "GOLDEN_CERT",
})

for _name in dir(_original):
    if _name.startswith("__") or _name in globals():
        continue
    globals()[_name] = getattr(_original, _name)

