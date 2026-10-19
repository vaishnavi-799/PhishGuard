"""Tiny local servers used to test the network code without internet access."""
from __future__ import annotations

import socket
import socketserver
import ssl
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def start_http(handler_cls, certfile=None, keyfile=None):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def route_handler(routes):
    """routes: {path: (status, headers_dict, body_bytes | callable(handler))}"""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            r = routes.get(self.path.split("?")[0]) or routes.get("*") or (404, {}, b"not found")
            status, headers, body = r
            if callable(body):
                return body(self)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return H


def start_tls_listener(certfile, keyfile):
    """Accepts TLS handshakes then closes. Enough for certificate probing."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    raw = socket.socket()
    raw.bind(("127.0.0.1", 0))
    raw.listen(8)
    stop = threading.Event()

    def loop():
        raw.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = raw.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with ctx.wrap_socket(c, server_side=True) as s:
                    s.recv(1)
            except (ssl.SSLError, OSError):
                pass
    threading.Thread(target=loop, daemon=True).start()
    return raw.getsockname()[1], lambda: (stop.set(), raw.close())


def start_dns(handler, tcp=False):
    """handler(request_bytes) -> list[bytes] datagrams to send back (UDP) / single response (TCP)."""
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    port = udp.getsockname()[1]
    stop = threading.Event()

    def udp_loop():
        udp.settimeout(0.2)
        while not stop.is_set():
            try:
                data, addr = udp.recvfrom(512)
            except (socket.timeout, OSError):
                continue
            for out in handler(data, "udp"):
                udp.sendto(out, addr)
    threading.Thread(target=udp_loop, daemon=True).start()
    tsock = None
    if tcp:
        tsock = socket.socket()
        tsock.bind(("127.0.0.1", port))
        tsock.listen(4)

        def tcp_loop():
            tsock.settimeout(0.2)
            while not stop.is_set():
                try:
                    c, _ = tsock.accept()
                except (socket.timeout, OSError):
                    continue
                with c:
                    n = struct.unpack("!H", c.recv(2))[0]
                    req = c.recv(n)
                    for out in handler(req, "tcp"):
                        c.sendall(struct.pack("!H", len(out)) + out)
        threading.Thread(target=tcp_loop, daemon=True).start()
    return port, lambda: (stop.set(), udp.close(), tsock and tsock.close())
