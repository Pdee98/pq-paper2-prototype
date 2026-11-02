"""Usage: python -B -m src.paper2.model path/to/config.json."""

import argparse
import json
from pathlib import Path

from . import run_model


def main():
    parser = argparse.ArgumentParser(description="Paper 2 verification model")
    parser.add_argument("config", type=Path, help="JSON config; output_dir must be outside repository")
    args = parser.parse_args()
    log, manifest = run_model(json.loads(args.config.read_text(encoding="utf-8")))
    print(json.dumps({"event_log": str(log), "manifest": str(manifest)}))


if __name__ == "__main__":
    main()
