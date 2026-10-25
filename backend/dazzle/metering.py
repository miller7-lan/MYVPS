"""Exact integer payload observations from the loopback sing-box 1.14 API.

This module neither installs an API listener nor controls sing-box. It is opt-in
and used against isolated local test workers in phase 1. Never bill NIC bytes or
infer provider resets from these counters.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
import http.client
import ipaddress
import struct
from typing import BinaryIO, Iterator

MAX_FRAME = 1024 * 1024
MAX_I64 = 2**63 - 1


class MeteringError(Exception):
    """Safe error whose message never includes an API secret."""


def _read_exact(stream: BinaryIO, size: int, *, allow_eof: bool = False) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = stream.read(size - len(chunks))
        if not part:
            if not chunks and allow_eof:
                return b""
            raise MeteringError("Truncated gRPC-Web frame")
        chunks.extend(part)
    return bytes(chunks)


def grpc_frames(stream: BinaryIO, *, require_trailer: bool = True) -> Iterator[bytes]:
    """Bounded framing only; protobuf messages use generated protobuf classes."""
    trailer_seen = False
    while True:
        header = _read_exact(stream, 5, allow_eof=True)
        if not header:
            if require_trailer and not trailer_seen:
                raise MeteringError("gRPC-Web closed without successful trailer")
            return
        flags, length = struct.unpack(">BI", header)
        if length > MAX_FRAME:
            raise MeteringError("gRPC-Web frame exceeds limit")
        payload = _read_exact(stream, length)
        if flags == 0x80:
            try:
                trailers = dict(line.split(":", 1) for line in payload.decode("ascii").split("\r\n") if line)
                status = trailers.get("grpc-status", "").strip()
            except (UnicodeError, ValueError) as exc:
                raise MeteringError("Invalid gRPC-Web trailer") from exc
            if status != "0":
                raise MeteringError("gRPC request failed")
            trailer_seen = True
            return
        if flags != 0:
            raise MeteringError("Compressed or unknown gRPC-Web frame is unsupported")
        yield payload


@dataclass(frozen=True)
class MeterSample:
    epoch: str
    uplink: int
    downlink: int
    at: str
    traffic_available: bool = True

    def validate(self) -> None:
        if not self.epoch or len(self.epoch) > 128:
            raise MeteringError("Missing instance epoch")
        for value in (self.uplink, self.downlink):
            if type(value) is not int or not 0 <= value <= MAX_I64:
                raise MeteringError("Invalid integer payload counter")
        timestamp = datetime.fromisoformat(self.at.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise MeteringError("Sample requires timezone")
        if not self.traffic_available:
            raise MeteringError("Native traffic counters are unavailable")


@dataclass
class NativeAPI:
    host: str
    port: int
    secret: str = field(repr=False)
    timeout: float = 3.0

    def __post_init__(self) -> None:
        try:
            if not ipaddress.ip_address(self.host).is_loopback:
                raise ValueError()
        except ValueError as exc:
            raise MeteringError("Native API must use a literal loopback address") from exc
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise MeteringError("Invalid API port")
        if not self.secret or len(self.secret) < 24 or any(c in self.secret for c in "\r\n"):
            raise MeteringError("Native API requires a strong nonempty secret")
        if not 0 < self.timeout <= 10:
            raise MeteringError("API timeout outside supported range")

    def _open(self, method: str, payload: bytes):
        # http.client does not inherit HTTP_PROXY and does not follow redirects.
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            body = struct.pack(">BI", 0, len(payload)) + payload
            connection.request("POST", "/daemon.StartedService/" + method, body, {
                "Content-Type": "application/grpc-web+proto", "X-Grpc-Web": "1",
                "Authorization": "Bearer " + self.secret,
            })
            response = connection.getresponse()
            if response.status != 200 or not response.getheader("Content-Type", "").startswith("application/grpc-web"):
                raise MeteringError("Native API returned an invalid HTTP response")
            return connection, response
        except Exception:
            connection.close()
            raise MeteringError("Native API connection failed") from None

    def started_at(self) -> str:
        from .proto.traffic_pb2 import StartedAt
        connection, response = self._open("GetStartedAt", b"")
        try:
            values = list(grpc_frames(response))
            if len(values) != 1:
                raise MeteringError("Missing worker start epoch")
            message = StartedAt.FromString(values[0])
            if message.startedAt <= 0:
                raise MeteringError("Invalid worker start epoch")
            return str(message.startedAt)
        except MeteringError:
            raise
        except Exception:
            raise MeteringError("Native API epoch decode failed") from None
        finally:
            connection.close()

    def stream(self) -> Iterator[MeterSample]:
        from .proto.traffic_pb2 import Status, SubscribeStatusRequest
        epoch = self.started_at()
        request = SubscribeStatusRequest(interval=1_000_000_000)
        connection, response = self._open("SubscribeStatus", request.SerializeToString())
        try:
            identity_checked = False
            for payload in grpc_frames(response):
                # The unary epoch and stream use different HTTP connections. A
                # restart between them must never attach new totals to an old epoch.
                if not identity_checked:
                    if self.started_at() != epoch:
                        raise MeteringError("Worker epoch changed while opening traffic stream")
                    identity_checked = True
                try:
                    message = Status.FromString(payload)
                    sample = MeterSample(epoch, message.uplinkTotal, message.downlinkTotal,
                                         datetime.now(timezone.utc).isoformat(), message.trafficAvailable)
                    sample.validate()
                except Exception:
                    raise MeteringError("Native API traffic decode failed") from None
                yield sample
        finally:
            connection.close()


@dataclass
class CounterTracker:
    """Testable gap detection. Persistence and quota enforcement belong to Store."""
    last: MeterSample | None = None

    def advance(self, sample: MeterSample) -> dict:
        sample.validate()
        old = self.last
        self.last = sample
        if old is None:
            return {"upload": sample.uplink, "download": sample.downlink,
                    "trusted": sample.uplink == sample.downlink == 0, "reason": "initial_baseline"}
        if sample.epoch != old.epoch:
            return {"upload": sample.uplink, "download": sample.downlink,
                    "trusted": False, "reason": "worker_restarted_unknown_gap"}
        if sample.uplink < old.uplink or sample.downlink < old.downlink:
            return {"upload": 0, "download": 0, "trusted": False, "reason": "counter_regression"}
        elapsed = (datetime.fromisoformat(sample.at.replace("Z", "+00:00")) -
                   datetime.fromisoformat(old.at.replace("Z", "+00:00"))).total_seconds()
        return {"upload": sample.uplink - old.uplink, "download": sample.downlink - old.downlink,
                "trusted": 0 <= elapsed <= 5,
                "reason": "normal" if 0 <= elapsed <= 5 else "unknown_sample_gap"}
