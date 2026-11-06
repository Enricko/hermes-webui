"""Trusted byte relays in a loopback-only namespace; never mounted in the Agent."""

import os
from pathlib import Path
import select
import signal
import socket
import socketserver
import threading


class BoundedServer(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True

    def server_activate(self):
        self.slots = threading.BoundedSemaphore(96)
        super().server_activate()

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class UnixServer(BoundedServer, socketserver.UnixStreamServer):
    pass


class TCPServer(BoundedServer, socketserver.TCPServer):
    pass


def handler(destination):
    class Relay(socketserver.BaseRequestHandler):
        def handle(self):
            remote = socket.socket(socket.AF_UNIX if isinstance(destination, str) else socket.AF_INET)
            try:
                remote.settimeout(5)
                remote.connect(destination)
                remote.settimeout(None)
                while True:
                    ready, _, _ = select.select([self.request, remote], [], [], 1)
                    for source in ready:
                        chunk = source.recv(65536)
                        if not chunk:
                            return
                        (remote if source is self.request else self.request).sendall(chunk)
            except (OSError, TimeoutError):
                return
            finally:
                remote.close()
    return Relay


def main():
    # These are fixed paths/ports, never Docker targets supplied by a client.
    endpoint = Path('/relay/webui.sock')
    if endpoint.exists() or endpoint.is_symlink():
        endpoint.unlink()
    servers = [UnixServer(str(endpoint), handler(('127.0.0.1', 8787))),
               TCPServer(('127.0.0.1', 8000), handler('/broker/provider.sock')),
               TCPServer(('127.0.0.1', 8001), handler('/broker/egress.sock'))]
    os.chmod(endpoint, 0o660)
    stopping = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda _sig, _frame: stopping.set())
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    stopping.wait()
    for server in servers:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
