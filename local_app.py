"""Local dashboard backend. Only permits invoking this project's Lambda scanner."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import os
import sys
import threading
import webbrowser
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
DASH = ROOT / "dashboard"
sys.path.insert(0, str(ROOT / "src"))
from security_scanner_v2 import run_scan

PROFILE = os.environ.get("AWS_PROFILE", "scanner")
REGION = os.environ.get("SCANNER_REGION", "eu-north-1")
os.environ.setdefault("AWS_PROFILE", PROFILE)
os.environ.setdefault("AWS_REGION", REGION)
os.environ.setdefault("AWS_DEFAULT_REGION", REGION)

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DASH), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_POST(self):
        if self.path != "/api/scan":
            self.send_error(404)
            return
        try:
            import boto3
            session = None
            try:
                session = boto3.Session(profile_name=PROFILE, region_name=REGION)
            except Exception:
                session = boto3.Session(region_name=REGION)
            report = run_scan(REGION, session=session)
            data_path = DASH / "dashboard-data.json"
            try:
                previous = json.loads(data_path.read_text())
            except (OSError, json.JSONDecodeError):
                previous = {}
            latest_scan = {
                key: report[key]
                for key in ("scan_time", "region", "scan_status", "resources_scanned", "findings", "errors")
            }
            history = [{
                "scan_time": report["scan_time"],
                "scan_status": report["scan_status"],
                "finding_count": len(report["findings"]),
            }]
            history.extend(previous.get("scan_history", []))
            data_path.write_text(json.dumps({
                "latest_scan": latest_scan,
                "scan_history": history[:5],
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }, indent=2) + "\n")
            summary = {
                "scan_status": report["scan_status"],
                "region": REGION,
                "resources_scanned": sum(report["resources_scanned"].values()),
                "findings": len(report["findings"]),
                "errors": report["errors"],
            }
            self.send_json(200, {"ok": True, "result": summary,
                                 "command": f"Read-only AWS scan · profile {PROFILE} · {REGION}"})
        except Exception as exc:
            self.send_json(500, {"ok": False, "error": str(exc)})

    def send_json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    print("Dashboard: http://localhost:8000 (Ctrl+C to stop)")
    threading.Timer(1.0, lambda: webbrowser.open("http://localhost:8000")).start()
    ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
