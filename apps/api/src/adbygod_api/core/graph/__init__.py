import sys

from . import coverage_graph_service as _coverage_graph_service

# Publish the expanded graph service through the canonical import path.
sys.modules.setdefault(__name__ + ".graph_service", _coverage_graph_service)
