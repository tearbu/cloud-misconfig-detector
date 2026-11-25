#!/usr/bin/env python3
"""Feed every sample event through the evaluator and print findings.

The samples are fictional CloudTrail events in the EventBridge
"AWS API Call via CloudTrail" shape. Eleven of them are
misconfigurations or risky actions that should produce findings.
Five are benign lookalikes that should produce none, and they
matter just as much: a detector that fires on safe changes trains
people to ignore it.

Usage: python3 run_demo.py
"""

import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))

import rules

SAMPLE_DIR = os.path.join(ROOT, "sample-events")


def main():
    paths = sorted(glob.glob(os.path.join(SAMPLE_DIR, "*.json")))
    print(f"Running {len(paths)} sample events through the detector...\n")
    total_findings = 0
    fired = 0
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            event = json.load(handle)
        findings = rules.evaluate_event(event)
        name = os.path.basename(path)
        detail = event.get("detail", {})
        identity = detail.get("userIdentity") or {}
        actor = identity.get("arn") or identity.get("userName") or "unknown"
        print(f"--- {name}")
        print(f"Event: {detail.get('eventName')} by {actor}")
        if not findings:
            print("Findings: none")
        else:
            fired += 1
            for finding in findings:
                total_findings += 1
                print(f"Finding: [{finding['severity'].upper()}] "
                      f"{finding['rule_id']} on {finding['resource']}")
                print(f"  {finding['explanation']}")
                print(f"  Fix: {finding['remediation']}")
        print()
    print(f"Demo complete: {total_findings} findings across {fired} of "
          f"{len(paths)} events. The other {len(paths) - fired} events "
          "were benign and produced no findings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
