"""Regenerate committed sanitized demo/schema after installing the project."""

import json
import shutil
import tempfile
from pathlib import Path

from routewitness.demo import generate
from routewitness.models import Incident
from routewitness.reports import sanitize, terminal
from routewitness.storage import Store

root = Path(__file__).resolve().parents[1]
destination = root / "docs" / "examples"
with tempfile.TemporaryDirectory() as directory:
    store = Store(Path(directory))
    bundle = generate(store)
    for name in ("report.html", "report.md", "shareable.json", "timeline.csv"):
        shutil.copyfile(bundle / name, destination / name)
    (destination / "terminal.txt").write_text(
        terminal(sanitize(store.load(bundle.name))) + "\n", encoding="utf-8", newline="\n"
    )
(root / "docs" / "incident.schema.json").write_text(
    json.dumps(Incident.model_json_schema(), indent=2) + "\n", encoding="utf-8", newline="\n"
)
