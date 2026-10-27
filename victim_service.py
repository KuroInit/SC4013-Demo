from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

HOST = "0.0.0.0"
PORT = 443
MODE = os.environ.get("POLICY_MODE", "vulnerable").lower()
ROLE_PATH = "/latest/meta-data/iam/security-credentials/"
ROLE_NAME = "waf-demo-role"
CERT = "/certs/lab.crt"
KEY = "/certs/lab.key"

CLIENTS = [
    ("NS-DEMO-1001", "Avery Example", "avery@example.invalid", "+1-202-555-0101", "100 Demo Avenue"),
    ("NS-DEMO-1002", "Jordan Sample", "jordan@example.invalid", "+1-202-555-0102", "200 Sample Street"),
    ("NS-DEMO-1003", "Casey Fiction", "casey@example.invalid", "+1-202-555-0103", "300 Fiction Road"),
    ("NS-DEMO-1004", "Riley Placeholder", "riley@example.invalid", "+1-202-555-0104", "400 Placeholder Lane"),
]


def resolve_mock_target(url: str) -> tuple[str, None] | None:
    """Map only the exact Capital One-style metadata path to the private mock service.

    The supplied metadata URL is never opened. A new URL is built with the fixed
    Docker service name, so this handler cannot become a general-purpose proxy.
    """
    if not isinstance(url, str) or len(url) > 256:
        return None
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme != "http" or parsed.netloc != "169.254.169.254" or port is not None:
        return None
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        return None
    if parsed.path == ROLE_PATH or parsed.path == ROLE_PATH + ROLE_NAME:
        return parsed.path, None
    return None


class LabDatabase:
    """Ephemeral SQLite storage for fictional clients, demo accounts and safe audit events."""

    def __init__(self, connection: sqlite3.Connection | None = None) -> None:
        self.lock = threading.RLock()
        self.connection = connection or sqlite3.connect(":memory:", check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        with self.lock:
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS clients (client_id TEXT PRIMARY KEY, full_name TEXT, email TEXT, phone TEXT, mailing_address TEXT)"
            )
            self.connection.executemany(
                "INSERT OR IGNORE INTO clients VALUES (?, ?, ?, ?, ?)", CLIENTS
            )
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS demo_users (user_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, salt BLOB NOT NULL, password_hash BLOB NOT NULL, created_at TEXT NOT NULL)"
            )
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS demo_sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL)"
            )
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS audit_events (event_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, event_type TEXT NOT NULL, actor TEXT NOT NULL, source TEXT NOT NULL, decision TEXT NOT NULL, detail TEXT NOT NULL)"
            )
            self.connection.commit()

    @staticmethod
    def _public_user(row: sqlite3.Row) -> dict:
        return {
            "user_id": row["user_id"],
            "display_name": row["display_name"],
            "email": row["email"],
            "created_at": row["created_at"],
        }

    def client_count(self) -> int:
        with self.lock:
            return self.connection.execute("SELECT COUNT(*) FROM clients").fetchone()[0]

    def register_account(self, display_name: str, email: str, password: str, source: str) -> dict:
        display_name = display_name.strip() if isinstance(display_name, str) else ""
        email = email.strip().lower() if isinstance(email, str) else ""
        if not 2 <= len(display_name) <= 60:
            raise ValueError("name must be 2–60 characters")
        if len(email) > 120 or not re.fullmatch(r"[a-z0-9._+-]+@example\.invalid", email):
            raise ValueError("use a synthetic @example.invalid email for this lab")
        if not isinstance(password, str) or not 12 <= len(password) <= 128:
            raise ValueError("password must be 12–128 characters")
        salt = secrets.token_bytes(16)
        password_hash = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        user_id = "NS-USER-" + secrets.token_hex(4).upper()
        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            with self.lock:
                self.connection.execute(
                    "INSERT INTO demo_users(user_id,display_name,email,salt,password_hash,created_at) VALUES(?,?,?,?,?,?)",
                    (user_id, display_name, email, salt, password_hash, created_at),
                )
                self.connection.commit()
        except sqlite3.IntegrityError:
            raise ValueError("an account with that demo email already exists") from None
        self.add_event(
            "ACCOUNT_CREATED", email, source, "SUCCESS",
            f"New client account {user_id} registered; password was not retained in the audit log.",
        )
        return {"user_id": user_id, "display_name": display_name, "email": email, "created_at": created_at}

    def login(self, email: str, password: str, source: str) -> tuple[dict | None, str | None]:
        email = email.strip().lower() if isinstance(email, str) else ""
        with self.lock:
            row = self.connection.execute(
                "SELECT * FROM demo_users WHERE email=?", (email,)
            ).fetchone()
        valid = False
        if row is not None and isinstance(password, str):
            candidate = hashlib.scrypt(password.encode(), salt=row["salt"], n=2**14, r=8, p=1, dklen=32)
            valid = hmac.compare_digest(candidate, row["password_hash"])
        if not valid:
            self.add_event("LOGIN_FAILED", email or "unknown", source, "DENY", "Login rejected; password omitted.")
            return None, None
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            self.connection.execute(
                "INSERT INTO demo_sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                (token_hash, row["user_id"], int(time.time()) + 3600),
            )
            self.connection.commit()
        user = self._public_user(row)
        self.add_event("LOGIN_SUCCESS", email, source, "ALLOW", f"Authenticated session created for {user['user_id']}.")
        return user, token

    def session_user(self, token: str | None) -> dict | None:
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            row = self.connection.execute(
                "SELECT u.* FROM demo_sessions s JOIN demo_users u ON s.user_id=u.user_id WHERE s.token_hash=? AND s.expires_at>?",
                (token_hash, int(time.time())),
            ).fetchone()
        return self._public_user(row) if row else None

    def logout(self, token: str | None) -> None:
        if not token:
            return
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            self.connection.execute("DELETE FROM demo_sessions WHERE token_hash=?", (token_hash,))
            self.connection.commit()

    def add_event(self, event_type: str, actor: str, source: str, decision: str, detail: str) -> None:
        event_id = "evt-" + uuid.uuid4().hex[:10]
        created_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        with self.lock:
            self.connection.execute(
                "INSERT INTO audit_events VALUES(?,?,?,?,?,?,?)",
                (event_id, created_at, event_type, actor[:120], source[:64], decision[:16], detail[:240]),
            )
            self.connection.commit()

    def events(self) -> list[dict]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT event_id,created_at,event_type,actor,source,decision,detail FROM audit_events ORDER BY rowid DESC LIMIT 100"
            ).fetchall()
        return [dict(row) for row in reversed(rows)]


DB = LabDatabase()


class VictimHandler(BaseHTTPRequestHandler):
    server_version = "Northstar-Client-Portal/4.8"
    sys_version = ""

    def log_message(self, fmt: str, *args) -> None:
        # Never log request bodies, passwords, session cookies or returned credentials.
        command = getattr(self, "command", "BAD_REQUEST")
        path = getattr(self, "path", "<malformed>").split("?")[0]
        print(f"[victim-access] {time.strftime('%H:%M:%S')} {command} {path}", flush=True)

    def send_bytes(self, status: int, payload: bytes, content_type: str, extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        self.send_header("X-Portal-Release", "2026.10.4")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def send_json(self, status: int, data: dict, extra_headers: dict[str, str] | None = None) -> None:
        self.send_bytes(status, json.dumps(data).encode(), "application/json; charset=utf-8", extra_headers)

    def read_body(self) -> dict:
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("invalid Content-Length") from None
        if not 0 <= size <= 16_384:
            raise ValueError("request body is too large")
        try:
            value = json.loads(self.rfile.read(size).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("request body must be JSON") from None
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    def source_ip(self) -> str:
        return self.client_address[0]

    def session_token(self) -> str | None:
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except Exception:
            return None
        morsel = cookies.get("ns_session")
        return morsel.value if morsel else None

    def current_user(self) -> dict | None:
        return DB.session_user(self.session_token())

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            self.serve_html("/app/index.html")
        elif path == "/security/audit":
            self.serve_html("/app/security.html")
        elif path == "/robots.txt":
            self.send_bytes(200, b"User-agent: *\nDisallow: /api/\nDisallow: /documents/\n", "text/plain; charset=utf-8")
        elif path in {"/api/auth/register", "/api/auth/login", "/api/auth/logout", "/api/document-preview"}:
            self.send_json(405, {"error": "method not allowed"}, {"Allow": "POST"})
        elif path == "/api/public/status":
            self.send_json(200, {"service": "northstar-client-portal", "version": "4.8", "status": "operational"})
        elif path == "/api/public/application-summary":
            self.send_json(200, {"applications_in_review": 1, "customer_records": DB.client_count(), "notice": "Synthetic local lab data"})
        elif path == "/api/me":
            user = self.current_user()
            if user:
                self.send_json(200, {"authenticated": True, "user": user})
            else:
                self.send_json(401, {"authenticated": False, "error": "login required"})
        elif path == "/api/audit/events":
            self.send_json(200, {"events": DB.events(), "notice": "Sanitized operator view; synthetic local lab only."})
        elif path == "/documents/sample-statement.txt":
            self.send_bytes(200, b"NORTHSTAR FINANCIAL - FICTIONAL SAMPLE STATEMENT\nNo real customer information.\n", "text/plain; charset=utf-8")
        elif path == "/health":
            self.send_json(200, {"ok": True, "service": "victim-web", "mode": MODE})
        else:
            self.send_json(404, {"error": "not found"})

    def serve_html(self, path: str) -> None:
        try:
            with open(path, "rb") as f:
                self.send_bytes(200, f.read(), "text/html; charset=utf-8")
        except OSError:
            self.send_json(500, {"error": "portal asset unavailable"})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        try:
            body = self.read_body()
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return
        if path == "/api/auth/register":
            self.register(body)
        elif path == "/api/auth/login":
            self.login(body)
        elif path == "/api/auth/logout":
            self.logout()
        elif path == "/api/document-preview":
            self.document_preview(body)
        else:
            self.send_json(404, {"error": "not found"})

    def register(self, body: dict) -> None:
        try:
            user = DB.register_account(
                body.get("display_name"), body.get("email"), body.get("password"), self.source_ip()
            )
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return
        print(f"[audit] account created user_id={user['user_id']} source={self.source_ip()}", flush=True)
        self.send_json(201, {"created": True, "user": user, "notice": "Synthetic demo account; no email was sent."})

    def login(self, body: dict) -> None:
        email = body.get("email", "")
        password = body.get("password", "")
        if not isinstance(email, str) or not isinstance(password, str):
            self.send_json(400, {"error": "email and password must be strings"})
            return
        user, token = DB.login(email, password, self.source_ip())
        if user is None or token is None:
            self.send_json(401, {"error": "invalid demo email or password"})
            return
        print(f"[audit] login success actor={user['email']} source={self.source_ip()}", flush=True)
        cookie = f"ns_session={token}; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Strict"
        self.send_json(200, {"authenticated": True, "user": user}, {"Set-Cookie": cookie})

    def logout(self) -> None:
        user = self.current_user()
        if user:
            DB.add_event("LOGOUT", user["email"], self.source_ip(), "SUCCESS", "Demo session ended.")
        DB.logout(self.session_token())
        self.send_json(200, {"logged_out": True}, {"Set-Cookie": "ns_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"})

    def document_preview(self, body: dict) -> None:
        user = self.current_user()
        if not user:
            DB.add_event("PREVIEW_UNAUTHENTICATED", "anonymous", self.source_ip(), "DENY", "Document preview rejected; sign-in required.")
            self.send_json(401, {"error": "sign in before using document preview"})
            return
        actor = user["email"]
        target = body.get("url")
        if target == "https://victim/documents/sample-statement.txt":
            DB.add_event("DOCUMENT_PREVIEW", actor, self.source_ip(), "ALLOW", "Customer opened the fixed harmless sample statement.")
            self.send_json(200, {"status": "preview-ready", "text": "FICTIONAL SAMPLE STATEMENT — no customer data"})
            return
        DB.add_event("DOCUMENT_PREVIEW_REQUEST", actor, self.source_ip(), "RECEIVED", "Authenticated account requested a server-side document preview.")
        if MODE == "protected":
            DB.add_event("WAF_METADATA_BLOCK", actor, self.source_ip(), "DENY", "Protected policy blocked the metadata destination before any internal request.")
            print("[waf] DENY server-side request: protected policy", flush=True)
            self.send_json(403, {"error": "WAF policy blocked metadata destination"})
            return
        mapped = resolve_mock_target(target)
        if mapped is None:
            DB.add_event("WAF_DESTINATION_BLOCK", actor, self.source_ip(), "DENY", "Requested destination is outside the exact local simulation allowlist.")
            print("[waf] DENY server-side request: destination not in local simulation allowlist", flush=True)
            self.send_json(403, {"error": "destination is outside the local simulation allowlist"})
            return
        mock_path, _ = mapped
        DB.add_event("WAF_MISCONFIGURATION_EXPLOITED", actor, self.source_ip(), "ALLOW", "Document-preview proxy relayed a link-local metadata path to the private mock service.")
        internal_url = "http://mock-metadata:8082" + mock_path
        print("[waf] ALLOW fixed metadata-path reconstruction; mapping to private mock service", flush=True)
        try:
            with urlopen(Request(internal_url, headers={"Accept": "application/json,text/plain"}), timeout=3) as response:
                content = response.read(8192)
                ctype = response.headers.get("Content-Type", "text/plain")
                status = response.status
        except Exception as exc:
            DB.add_event("MOCK_METADATA_ERROR", actor, self.source_ip(), "ERROR", f"Private mock metadata service unavailable ({type(exc).__name__}).")
            print(f"[waf] mock metadata unavailable: {type(exc).__name__}", flush=True)
            self.send_json(502, {"error": "private mock metadata service unavailable"})
            return
        if mock_path == ROLE_PATH:
            role_name = content.decode("utf-8", errors="replace").strip()
            DB.add_event("METADATA_ROLE_DISCOVERED", actor, self.source_ip(), "SIMULATED", f"Mock metadata returned workload role name {role_name}.")
        else:
            DB.add_event("METADATA_CREDENTIALS_RETURNED", actor, self.source_ip(), "SIMULATED", "Synthetic temporary role credentials returned via SSRF; secret and token values redacted.")
        print(f"[ssrf] request mapped to mock-metadata path={mock_path} status={status}", flush=True)
        self.send_json(200, {"http_status": status, "content_type": ctype, "body": content.decode("utf-8", errors="replace"),
                             "lab_notice": "Real link-local metadata was never contacted."})


def main() -> None:
    if MODE not in {"vulnerable", "protected"}:
        raise SystemExit("POLICY_MODE must be vulnerable or protected")
    server = ThreadingHTTPServer((HOST, PORT), VictimHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(CERT, KEY)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"Northstar fictional victim portal listening on HTTPS :{PORT} (mode={MODE})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
