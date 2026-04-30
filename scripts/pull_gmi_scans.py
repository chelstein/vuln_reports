#!/usr/bin/env python3
"""
Pull every historical run of every GMI-named scan from a Nessus/Tenable host
and save each as HTML into ./scans/gmi/.

Usage:
    export TENABLE_ACCESS_KEY=...    # NEVER hardcode
    export TENABLE_SECRET_KEY=...
    export TENABLE_URL=https://137.184.89.60:8834
    python3 scripts/pull_gmi_scans.py [--match GMI] [--insecure]
"""
import argparse
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3


def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")


class Nessus:
    def __init__(self, base_url: str, access_key: str, secret_key: str, verify: bool):
        self.base = base_url.rstrip("/")
        self.s = requests.Session()
        self.s.headers["X-ApiKeys"] = f"accessKey={access_key}; secretKey={secret_key}"
        self.s.headers["Accept"] = "application/json"
        self.s.verify = verify

    def _req(self, method: str, path: str, **kw):
        r = self.s.request(method, f"{self.base}{path}", timeout=60, **kw)
        r.raise_for_status()
        return r

    def list_scans(self):
        return self._req("GET", "/scans").json().get("scans", []) or []

    def scan_detail(self, scan_id: int):
        return self._req("GET", f"/scans/{scan_id}").json()

    def export_request(self, scan_id: int, history_id: int | None) -> int:
        body = {"format": "html", "chapters": "vuln_by_host;vuln_hosts_summary"}
        params = {"history_id": history_id} if history_id else {}
        r = self._req("POST", f"/scans/{scan_id}/export", json=body, params=params)
        return r.json()["file"]

    def export_status(self, scan_id: int, file_id: int) -> str:
        return self._req("GET", f"/scans/{scan_id}/export/{file_id}/status").json()["status"]

    def export_download(self, scan_id: int, file_id: int) -> bytes:
        return self._req("GET", f"/scans/{scan_id}/export/{file_id}/download").content

    def export(self, scan_id: int, history_id: int | None, poll: float = 2.0, timeout: float = 600) -> bytes:
        file_id = self.export_request(scan_id, history_id)
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self.export_status(scan_id, file_id)
            if status == "ready":
                return self.export_download(scan_id, file_id)
            if status not in ("loading", "processing"):
                raise RuntimeError(f"unexpected export status: {status}")
            time.sleep(poll)
        raise TimeoutError(f"export {scan_id}/{file_id} did not complete in {timeout}s")


def fmt_ts(epoch) -> str:
    if not epoch:
        return "unknown"
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--match", default="GMI", help="case-insensitive substring to match scan names")
    ap.add_argument("--out", default="scans/gmi", help="output directory")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed)")
    args = ap.parse_args()

    base = os.environ.get("TENABLE_URL")
    ak = os.environ.get("TENABLE_ACCESS_KEY")
    sk = os.environ.get("TENABLE_SECRET_KEY")
    missing = [k for k, v in {"TENABLE_URL": base, "TENABLE_ACCESS_KEY": ak, "TENABLE_SECRET_KEY": sk}.items() if not v]
    if missing:
        print(f"error: missing env vars: {', '.join(missing)}", file=sys.stderr)
        return 2

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    nessus = Nessus(base, ak, sk, verify=not args.insecure)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    needle = args.match.lower()
    matches = [s for s in nessus.list_scans() if needle in (s.get("name") or "").lower()]
    print(f"found {len(matches)} scans matching {args.match!r}")
    if not matches:
        return 0

    total = 0
    failed = 0
    for s in matches:
        scan_id = s["id"]
        scan_name = s.get("name") or f"scan-{scan_id}"
        try:
            detail = nessus.scan_detail(scan_id)
        except requests.HTTPError as e:
            print(f"  ! {scan_name} ({scan_id}): cannot read detail: {e}")
            failed += 1
            continue
        history = detail.get("history") or []
        print(f"\n== {scan_name} (id={scan_id}, runs={len(history)})")

        runs = history if history else [{"history_id": None, "last_modification_date": s.get("last_modification_date")}]
        for h in runs:
            hid = h.get("history_id")
            ts = fmt_ts(h.get("last_modification_date") or h.get("creation_date"))
            fname = f"{slug(scan_name)}__{ts}__{hid or 'latest'}.html"
            dest = out_dir / fname
            if dest.exists() and dest.stat().st_size > 0:
                print(f"  - skip (exists): {fname}")
                continue
            try:
                data = nessus.export(scan_id, hid)
                dest.write_bytes(data)
                total += 1
                print(f"  + {fname} ({len(data):,} bytes)")
            except Exception as e:
                failed += 1
                print(f"  ! {fname}: {e}")

    print(f"\ndone: {total} downloaded, {failed} failed, into {out_dir}/")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
