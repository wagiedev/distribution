#!/usr/bin/env python3

import argparse
import json
import os
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("--release-id", required=True, type=int)
parser.add_argument("--asset", required=True)
parser.add_argument("--name", required=True)
args = parser.parse_args()
if args.release_id != 77 or Path(args.asset).name != args.name:
    raise SystemExit("upload did not target the exact release object and asset name")
state = Path(os.environ["FAKE_GH_STATE"])
with (state / "uploads.log").open("a", encoding="utf-8") as handle:
    handle.write(f"{args.release_id}\t{args.name}\n")
print(json.dumps({"id": 1, "name": args.name}))
