"""Child process for transaction tests. Kill only this child, never a service."""
import os
from pathlib import Path
import signal
import sys

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root/"app"))
import agent

workspace = Path(sys.argv[1]).resolve()
assert workspace.parent == root and workspace.name.startswith("tmp")
agent.BASE = workspace
agent.CFG_DIR = workspace/"config"
agent.CONFIG = agent.CFG_DIR/"config.yaml"
agent.STATE = workspace/"state"
agent.restart_checked = lambda _: None
original = agent.save_atomic
point = sys.argv[2]


def inject(path, data):
    if point == "before_replace" and path == agent.CONFIG:
        os.kill(os.getpid(), signal.SIGKILL)
    original(path, data)
    if ((point == "after_replace" and path == agent.CONFIG) or
            (point == "after_commit" and path == agent.STATE/"last-change.json")):
        os.kill(os.getpid(), signal.SIGKILL)


agent.save_atomic = inject
agent.reorder(["REGION_US","REGION_TW","REGION_JP","REGION_SG"])
raise AssertionError("fault point not reached")
