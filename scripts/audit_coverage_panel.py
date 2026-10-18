"""Compare one public metadata panel against two explicitly selected catalogs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

if __package__ in (None, ""):
    source = str(Path(__file__).resolve().parents[1] / "src")
    if source not in sys.path:
        sys.path.insert(0, source)

from uvault.catalog import load_registry
from uvault.coverage_audit import audit_panel


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel", required=True)
    parser.add_argument("--registry", required=True, help="Current catalog URL or local expanded index")
    parser.add_argument("--baseline-registry", required=True, help="Explicit baseline catalog; no implicit mutable default")
    parser.add_argument("--out", required=True, help="New JSON output file; parent directory must exist")
    args = parser.parse_args(argv)
    try:
        destination = Path(args.out)
        if destination.exists() or destination.is_symlink():
            raise ValueError("Output already exists; audit never overwrites evidence")
        if not destination.parent.is_dir():
            raise ValueError("Output parent must already exist")
        data = Path(args.panel).read_bytes()
        panel = json.loads(data.decode("utf-8-sig"))
        baseline = audit_panel(panel, load_registry(args.baseline_registry))
        current = audit_panel(panel, load_registry(args.registry))
        deltas = {name: {"baseline": baseline["summary"]["metrics"][name],
                         "current": metric,
                         "numeratorChange": metric["numerator"] - baseline["summary"]["metrics"][name]["numerator"]}
                  for name, metric in current["summary"]["metrics"].items()}
        result = {"schemaVersion": "1.0", "kind": "same-panel-catalog-coverage-comparison",
                  "panelFileSha256": hashlib.sha256(data).hexdigest(),
                  "samePanelContent": baseline["panelContentSha256"] == current["panelContentSha256"],
                  "baseline": baseline, "current": current, "metricComparison": deltas,
                  "completeRuntimeDependencyCoverage": {"baselineRatio": None, "currentRatio": None,
                                                         "reason": "runtime-consumer-denominator-unproven"}}
        with destination.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(result, output, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
            output.write("\n")
        print(json.dumps({"schemaVersion": "1.0", "samePanelContent": result["samePanelContent"],
                          "baselineCommit": baseline["catalogCommit"], "currentCommit": current["catalogCommit"],
                          "projectCount": len(current["projects"]), "metricComparison": deltas}, ensure_ascii=False))
        return 0
    except (ValueError, OSError, TypeError, KeyError) as error:
        message = str(error) if isinstance(error, ValueError) else "Unable to read, audit or exclusively write the requested inputs/output"
        print(json.dumps({"schemaVersion": "1.0", "error": type(error).__name__, "message": message}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
