from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


_ORIGINAL_PATH = Path(__file__).with_name("bloodhound.py")
_SPEC = importlib.util.spec_from_file_location("_adbygod_original_bloodhound", _ORIGINAL_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError(f"Cannot load original BloodHound parser from {_ORIGINAL_PATH}")
_original = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("_adbygod_original_bloodhound", _original)
_SPEC.loader.exec_module(_original)


_EXPANDED_ACE_TO_EDGE = {
    "ReadLAPSPassword": "READ_LAPS_PASSWORD",
    "ReadGMSAPassword": "READ_GMSA_PASSWORD",
    "WriteSPN": "WRITE_SPN",
    "AddKeyCredentialLink": "ADD_KEY_CREDENTIAL_LINK",
    "WriteGPLink": "WRITE_GP_LINK",
    "WriteAccountRestrictions": "WRITE_ACCOUNT_RESTRICTIONS",
    "ManageCA": "MANAGE_CA",
    "ManageCertificates": "MANAGE_CERTIFICATES",
    "GoldenCert": "GOLDEN_CERT",
    "CAPrivateKeyControl": "CA_PRIVATE_KEY_CONTROL",
    "SQLAdmin": "SQL_ADMIN",
    "HasSession": "HAS_SESSION",
}
_original._ACE_TO_EDGE.update(_EXPANDED_ACE_TO_EDGE)


class BloodHoundParser(_original.BloodHoundParser):
    """BloodHound parser with coverage-expansion edge mappings."""


for _name in dir(_original):
    if _name.startswith("__") or _name in globals():
        continue
    globals()[_name] = getattr(_original, _name)

