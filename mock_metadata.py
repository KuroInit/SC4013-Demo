from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json

ROLE = "waf-demo-role"
CREDENTIALS = {
    "Code": "Success",
    "LastUpdated": "2030-01-01T00:00:00Z",
    "Type": "simulated",
    "AccessKeyId": "SIMAKIA-NORTHSTAR-DEMO",
    "SecretAccessKey": "SIMULATED-ONLY-NOT-AWS-SECRET-8B31",
    "Token": "SIMULATED-ONLY-NOT-AWS-SESSION-9F42",
    "Expiration": "2030-01-01T01:00:00Z",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "EC2-metadata-mock/1.0"
    sys_version = ""

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        if self.path == "/health":
            status, body = 200, {"ok": True}
        elif self.path == "/latest/meta-data/iam/security-credentials/":
            status, body = 200, ROLE + "\n"
        elif self.path == "/latest/meta-data/iam/security-credentials/" + ROLE:
            status, body = 200, CREDENTIALS
        else:
            status, body = 404, {"error": "not found"}
        raw = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        content_type = "text/plain; charset=utf-8" if isinstance(body, str) else "application/json; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8082), Handler)
    print("mock metadata listening on private backend :8082 (HTTP, no host port)", flush=True)
    server.serve_forever()
