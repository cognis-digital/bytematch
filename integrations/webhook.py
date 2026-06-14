#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(
        description="POST JSON findings from stdin to a webhook URL."
    )
    ap.add_argument("--url", required=True, help="Destination URL (https://...)")
    ap.add_argument(
        "--header",
        action="append",
        default=[],
        help="Extra request header in 'Key: Value' form (repeatable)",
    )
    args = ap.parse_args()

    # Basic URL sanity check — must be http(s).
    if not args.url.lower().startswith(("http://", "https://")):
        print(
            f"error: --url must start with http:// or https://, got: {args.url!r}",
            file=sys.stderr,
        )
        return 2

    payload = sys.stdin.read().encode("utf-8")
    if not payload:
        print("error: no JSON payload on stdin", file=sys.stderr)
        return 2

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        if ":" not in h:
            print(
                f"error: invalid --header {h!r}: expected 'Key: Value' format",
                file=sys.stderr,
            )
            return 2
        k, _, v = h.partition(":")
        req.add_header(k.strip(), v.strip())

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as exc:
        print(f"webhook HTTP error: {exc.code} {exc.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"webhook error: {exc.reason}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"webhook error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
