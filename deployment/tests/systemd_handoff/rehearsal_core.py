#!/usr/bin/python3
"""Rehearsal Core stand-in: loopback TCP echo on the public port, counters on the API port.

Accepts the pinned core's `check -c FILE` and `run -c FILE -D DIR` command shape so
the unmodified production member/admin unit templates can start it.
"""
import json
import os
import signal
import socketserver
import sys
import threading
import time


def main():
    if sys.argv[1:2] == ["check"]:
        return 0
    config = json.load(open(sys.argv[sys.argv.index("-c") + 1]))["fixture"]
    epoch, totals, lock = time.time_ns(), {"up": 0, "down": 0}, threading.Lock()
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())

    class Proxy(socketserver.StreamRequestHandler):
        def handle(self):
            for line in iter(self.rfile.readline, b""):
                reply = b"ACK " + line.strip() + b" " + str(os.getpid()).encode() + b"\n"
                with lock:
                    totals["up"] += len(line)
                    totals["down"] += len(reply)
                self.wfile.write(reply)
                self.wfile.flush()

    class Api(socketserver.StreamRequestHandler):
        def handle(self):
            with lock:
                frame = {"epoch": epoch, "up": totals["up"], "down": totals["down"]}
            self.wfile.write(json.dumps(frame).encode() + b"\n")

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    servers = [Server(("0.0.0.0", config["public_port"]), Proxy), Server(("127.0.0.1", config["api_port"]), Api)]
    for server in servers:
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True).start()
    stopped.wait()
    for server in servers:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
