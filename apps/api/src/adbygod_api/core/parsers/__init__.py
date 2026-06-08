import sys

from . import coverage_bloodhound as _coverage_bloodhound

# Publish the expanded BloodHound parser through the canonical import path.
sys.modules.setdefault(__name__ + ".bloodhound", _coverage_bloodhound)
