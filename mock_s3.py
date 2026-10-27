from __future__ import annotations

import os
import re
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import PurePosixPath
from urllib.parse import parse_qs, unquote, urlsplit

ACCESS_KEY = "SIMAKIA-NORTHSTAR-DEMO"
SECRET_KEY = "SIMULATED-ONLY-NOT-AWS-SECRET-8B31"
SESSION_TOKEN = "SIMULATED-ONLY-NOT-AWS-SESSION-9F42"
BUCKET = "northstar-client-data-demo"
DATA_ROOT = "/data"
CERT = "/certs/lab.crt"
KEY = "/certs/lab.key"


def access_key_from_auth(header: str, service: str = "s3") -> str | None:
    """Accept a SigV4-shaped header scoped to one of this lab's mock APIs.

    This mock checks the fake key, service scope and signature shape; it does
    not implement AWS cryptographic signature validation or contact AWS.
    """
    if service not in {"s3", "sts"} or not isinstance(header, str) or not header.startswith("AWS4-HMAC-SHA256 "):
        return None
    credential = re.search(r"(?:^|[, ]+)Credential=([^/, ]+)/[0-9]{8}/[a-z0-9-]+/([a-z0-9-]+)/aws4_request(?:[, ]|$)", header)
    signed = re.search(r"(?:^|[, ]+)SignedHeaders=([a-z0-9;_-]+)(?:[, ]|$)", header)
    signature = re.search(r"(?:^|[, ]+)Signature=([0-9a-fA-F]{64})(?:[, ]|$)", header)
    if not credential or not signed or not signature or credential.group(2) != service:
        return None
    return credential.group(1) if credential.group(1) == ACCESS_KEY else None


class Handler(BaseHTTPRequestHandler):
    server_version = "AmazonS3"
    sys_version = ""

    def log_message(self, fmt, *args):
        # Never log Authorization headers or returned object content.
        print(f"[mock-s3] {time.strftime('%H:%M:%S')} {self.command} {self.path.split('?')[0]}", flush=True)

    def send_body(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("x-amz-request-id", "DEMO" + time.strftime("%H%M%S"))
        self.send_header("x-amz-id-2", "LOCAL-SIMULATION-ONLY")
        self.send_header("Server", "AmazonS3")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def authorized(self, service: str = "s3") -> bool:
        return (access_key_from_auth(self.headers.get("Authorization", ""), service=service) == ACCESS_KEY
                and self.headers.get("x-amz-security-token") == SESSION_TOKEN)

    def sts_error(self, status: int, code: str, message: str):
        body = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><Error>"
                f"<Type>Sender</Type><Code>{code}</Code><Message>{message}</Message>"
                "</Error><RequestId>LOCAL-SIM</RequestId></ErrorResponse>").encode()
        self.send_body(status, body, "text/xml; charset=utf-8")

    def handle_sts(self):
        parsed = urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        if length > 8192:
            self.sts_error(413, "RequestEntityTooLarge", "Mock STS request exceeds lab limit")
            return
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        params = parse_qs(parsed.query)
        params.update(parse_qs(body))
        if params.get("Action", [""])[0] != "GetCallerIdentity":
            self.sts_error(400, "InvalidAction", "Only GetCallerIdentity is implemented in this lab")
            return
        if not self.authorized(service="sts"):
            self.sts_error(403, "InvalidClientTokenId", "Synthetic lab role credential required")
            return
        response = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">"
                    "<GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/waf-demo-role/i-northstar-waf</Arn>"
                    "<UserId>AROANORTHSTARDEMO:i-northstar-waf</UserId><Account>123456789012</Account>"
                    "</GetCallerIdentityResult><ResponseMetadata><RequestId>LOCAL-SIM</RequestId>"
                    "</ResponseMetadata></GetCallerIdentityResponse>").encode()
        self.send_body(200, response, "text/xml; charset=utf-8")

    def xml_error(self, status: int, code: str, message: str):
        body = f"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{message}</Message><RequestId>LOCAL-SIM</RequestId></Error>".encode()
        self.send_body(status, body, "application/xml")

    def do_HEAD(self):
        self.handle_request()

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/" and parse_qs(parsed.query).get("Action") == ["GetCallerIdentity"]:
            self.handle_sts()
            return
        self.handle_request()

    def do_POST(self):
        if urlsplit(self.path).path == "/":
            self.handle_sts()
        else:
            self.xml_error(501, "NotImplemented", "Only the mock STS identity action uses POST")

    def handle_request(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            self.send_body(200, b'{"ok":true,"service":"mock-s3"}', "application/json")
            return
        if not self.authorized():
            self.xml_error(403, "AccessDenied", "Synthetic lab role credential required")
            return
        parts = [unquote(part) for part in parsed.path.strip("/").split("/") if part]
        if not parts:
            body = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    "<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner><ID>northstar-demo</ID><DisplayName>Northstar Demo Role</DisplayName></Owner><Buckets>"
                    f"<Bucket><Name>{BUCKET}</Name><CreationDate>2026-01-01T00:00:00.000Z</CreationDate></Bucket>"
                    "</Buckets></ListAllMyBucketsResult>").encode()
            self.send_body(200, body, "application/xml")
            return
        if parts[0] != BUCKET:
            self.xml_error(404, "NoSuchBucket", "The specified bucket does not exist in this lab")
            return
        if len(parts) == 1:
            filename = "client-records.json"
            size = os.path.getsize(os.path.join(DATA_ROOT, filename))
            body = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                    f"<Name>{BUCKET}</Name><Prefix></Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>"
                    f"<Contents><Key>{filename}</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>\"synthetic-demo-object\"</ETag><Size>{size}</Size><StorageClass>STANDARD</StorageClass></Contents>"
                    "</ListBucketResult>").encode()
            self.send_body(200, body, "application/xml")
            return
        if len(parts) != 2 or PurePosixPath(parts[1]).name != parts[1] or parts[1] != "client-records.json":
            self.xml_error(404, "NoSuchKey", "The requested synthetic object was not found")
            return
        filepath = os.path.join(DATA_ROOT, parts[1])
        try:
            with open(filepath, "rb") as f:
                data = f.read(64 * 1024)
        except OSError:
            self.xml_error(404, "NoSuchKey", "The requested synthetic object was not found")
            return
        self.send_body(200, data, "application/json", {"ETag": '"synthetic-demo-object"', "Last-Modified": "Thu, 01 Jan 2026 00:00:00 GMT"})


def main():
    server = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(CERT, KEY)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print("S3-compatible mock listening on private HTTPS :443", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
