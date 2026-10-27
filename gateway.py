from __future__ import annotations

import socket
import socketserver
import threading

FORWARDS = {8443: ("victim", 443), 7681: ("attacker-kali", 7681)}


def connect_upstream(host: str, port: int) -> socket.socket:
    """Bound the TCP handshake, then leave the tunnel blocking and idle-safe."""
    upstream = socket.create_connection((host, port), timeout=5)
    upstream.settimeout(None)
    return upstream


def pump(source: socket.socket, destination: socket.socket) -> None:
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            destination.sendall(data)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class ForwardHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        target_host, target_port = FORWARDS[self.server.server_address[1]]
        try:
            upstream = connect_upstream(target_host, target_port)
        except OSError as exc:
            print(f"[gateway] upstream unavailable for local port {self.server.server_address[1]}: {type(exc).__name__}", flush=True)
            return
        with upstream:
            client_to_service = threading.Thread(target=pump, args=(self.request, upstream), daemon=True)
            service_to_client = threading.Thread(target=pump, args=(upstream, self.request), daemon=True)
            client_to_service.start()
            service_to_client.start()
            client_to_service.join()
            service_to_client.join()


class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    servers = []
    for listen_port in FORWARDS:
        server = ThreadedTCPServer(("0.0.0.0", listen_port), ForwardHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        print(f"[gateway] TLS passthrough on :{listen_port} -> {FORWARDS[listen_port][0]}:{FORWARDS[listen_port][1]}", flush=True)
    try:
        threading.Event().wait()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
