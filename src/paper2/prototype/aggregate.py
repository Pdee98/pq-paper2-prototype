"""Strict summary-side verification: an unsealed aggregate is never accepted."""
import argparse
import json
from pathlib import Path
from .replay import verify_aggregate

def main():
    parser=argparse.ArgumentParser();parser.add_argument('directory',type=Path)
    args=parser.parse_args();result=verify_aggregate(args.directory)
    print(json.dumps(dict(passed=True,files=len(result['files']),provenance=result['provenance'])))

if __name__=='__main__':main()
