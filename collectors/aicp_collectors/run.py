"""CLI entry point.

  python -m aicp_collectors.run file --path ../samples/sample-events.jsonl
  python -m aicp_collectors.run m365                 # env: AICP_M365_TENANT_ID / CLIENT_ID / CLIENT_SECRET
  python -m aicp_collectors.run m365 --loop 300      # poll every 5 minutes (container mode)
  add --dry-run to print events instead of posting.
"""
import argparse
import logging
import os
import time

from .file_collector import FileCollector
from .m365 import M365Collector


def main() -> None:
    """Parse the command line, build the chosen collector and run it once or in a loop."""
    p = argparse.ArgumentParser(prog="aicp-collect")
    p.add_argument("collector", choices=["file", "m365"])
    p.add_argument("--api", default=os.environ.get("AICP_API_URL", "http://localhost:8000"))
    p.add_argument("--token", default=os.environ.get("AICP_INGEST_TOKEN", "dev-ingest-token-change-me"))
    p.add_argument("--path", help="JSONL path (file collector)")
    p.add_argument("--loop", type=int, default=0, help="seconds between runs; 0 = run once")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    common = {"api_url": a.api, "token": a.token, "dry_run": a.dry_run}
    if a.collector == "file":
        if not a.path:
            p.error("--path is required for the file collector")
        c = FileCollector(a.path, **common)
    else:
        c = M365Collector(**common)

    while True:
        c.run_once()
        if not a.loop:
            break
        time.sleep(a.loop)


if __name__ == "__main__":
    main()
