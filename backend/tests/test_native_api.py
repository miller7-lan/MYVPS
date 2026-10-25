"""Generated protobufs through a real ephemeral loopback HTTP fixture only."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import struct
import threading
import unittest

from dazzle.metering import MAX_FRAME, MeteringError, NativeAPI, grpc_frames
from dazzle.proto.traffic_pb2 import StartedAt, Status, SubscribeStatusRequest

SECRET = "isolated-test-only-native-api-secret-123456789"
EPOCH = 2**53 + 11
UPLOAD = 2**53 + 7
DOWNLOAD = 2**53 + 13


def frame(payload, flags=0):
    return struct.pack(">BI", flags, len(payload)) + payload


def trailer(status="0"):
    return frame(f"grpc-status: {status}\r\n".encode("ascii"), 0x80)


def epoch_response():
    return frame(StartedAt(startedAt=EPOCH).SerializeToString()) + trailer()


def status_response():
    return frame(Status(trafficAvailable=True, uplinkTotal=UPLOAD, downlinkTotal=DOWNLOAD).SerializeToString()) + trailer()


@contextmanager
def local_server(*, epoch=None, status=None, http_status=200, content_type="application/grpc-web+proto", expected_secret=SECRET, response_for=None):
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append({"path": self.path, "body": body, "authorized": self.headers.get("Authorization") == "Bearer " + expected_secret})
            if not requests[-1]["authorized"]:
                result_status, result_type, result_body = 401, "text/plain", b"Unauthorized"
            elif response_for is not None:
                result_status, result_type, result_body = response_for(self.path)
            elif self.path.endswith("/GetStartedAt"):
                result_status, result_type, result_body = http_status, content_type, epoch_response() if epoch is None else epoch
            elif self.path.endswith("/SubscribeStatus"):
                result_status, result_type, result_body = http_status, content_type, status_response() if status is None else status
            else:
                result_status, result_type, result_body = 404, "text/plain", b"Unknown method"
            self.send_response(result_status)
            self.send_header("Content-Type", result_type)
            self.send_header("Content-Length", str(len(result_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(result_body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        yield server.server_address[1], requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class NativeAPIHTTPTests(unittest.TestCase):
    def api(self, port, secret=SECRET):
        return NativeAPI("127.0.0.1", port, secret, timeout=1)

    def test_generated_started_at_preserves_exact_int64_above_double_precision(self):
        with local_server() as (port, requests):
            self.assertEqual(self.api(port).started_at(), str(EPOCH))
            self.assertEqual(requests[0]["path"], "/daemon.StartedService/GetStartedAt")
            self.assertTrue(requests[0]["authorized"])

    def test_generated_status_stream_preserves_integer_totals_and_request_interval(self):
        with local_server() as (port, requests):
            samples = list(self.api(port).stream())
            self.assertEqual(len(samples), 1)
            sample = samples[0]
            self.assertEqual((sample.epoch, sample.uplink, sample.downlink), (str(EPOCH), UPLOAD, DOWNLOAD))
            self.assertIs(type(sample.uplink), int)
            request = SubscribeStatusRequest.FromString(list(grpc_frames(io.BytesIO(requests[1]["body"]), require_trailer=False))[0])
            self.assertEqual(request.interval, 1_000_000_000)
            self.assertEqual(requests[1]["path"], "/daemon.StartedService/SubscribeStatus")

    def test_restart_between_epoch_and_stream_is_rejected_before_any_sample(self):
        count = 0
        def response(path):
            nonlocal count
            if path.endswith("GetStartedAt"):
                count += 1
                payload = StartedAt(startedAt=EPOCH + (1 if count > 1 else 0)).SerializeToString()
                return (200, "application/grpc-web+proto", frame(payload)+trailer())
            return (200, "application/grpc-web+proto", status_response())
        with local_server(response_for=response) as (port, _):
            with self.assertRaisesRegex(MeteringError, "epoch changed"):
                next(self.api(port).stream())

    def test_http_401_is_fail_closed_without_disclosing_bearer(self):
        with local_server(expected_secret="another-isolated-test-secret-123456789") as (port, requests):
            with self.assertRaises(MeteringError) as error:
                self.api(port).started_at()
            self.assertNotIn(SECRET, str(error.exception))
            self.assertEqual(len(requests), 1)

    def test_http_non_200_and_wrong_content_type_are_rejected(self):
        for values in ({"http_status": 500}, {"content_type": "application/json"}):
            with self.subTest(values=values), local_server(**values) as (port, _):
                with self.assertRaises(MeteringError):
                    self.api(port).started_at()

    def test_redirect_is_not_followed(self):
        with local_server(http_status=302) as (port, requests):
            with self.assertRaises(MeteringError):
                self.api(port).started_at()
            self.assertEqual(len(requests), 1)

    def test_stream_401_after_successful_epoch_is_rejected(self):
        def response(path):
            return (200, "application/grpc-web+proto", epoch_response()) if path.endswith("GetStartedAt") else (401, "text/plain", b"Unauthorized")
        with local_server(response_for=response) as (port, requests):
            with self.assertRaises(MeteringError):
                list(self.api(port).stream())
            self.assertEqual(len(requests), 2)

    def test_unknown_and_compressed_frame_flags_fail_closed(self):
        for flag in (1, 2, 0x81):
            with self.subTest(flag=flag), local_server(status=frame(b"unknown", flag) + trailer()) as (port, _):
                with self.assertRaises(MeteringError):
                    list(self.api(port).stream())

    def test_truncated_header_is_rejected(self):
        with local_server(epoch=b"\x00\x00\x00") as (port, _):
            with self.assertRaisesRegex(MeteringError, "Truncated"):
                self.api(port).started_at()

    def test_truncated_payload_is_rejected(self):
        broken = struct.pack(">BI", 0, 100) + b"short"
        with local_server(status=broken) as (port, _):
            with self.assertRaisesRegex(MeteringError, "Truncated"):
                list(self.api(port).stream())

    def test_oversized_frame_is_rejected_before_reading_payload(self):
        with local_server(status=struct.pack(">BI", 0, MAX_FRAME + 1)) as (port, _):
            with self.assertRaisesRegex(MeteringError, "exceeds"):
                list(self.api(port).stream())

    def test_stream_requires_successful_grpc_trailer(self):
        data = frame(Status(trafficAvailable=True, uplinkTotal=1).SerializeToString())
        for response in (data, data + trailer("16"), data + frame(b"not-a-trailer", 0x80)):
            with self.subTest(response=response), local_server(status=response) as (port, _):
                with self.assertRaises(MeteringError):
                    list(self.api(port).stream())

    def test_invalid_protobuf_payload_reports_safe_decode_error(self):
        with local_server(status=frame(b"\x80") + trailer()) as (port, _):
            with self.assertRaisesRegex(MeteringError, "decode") as error:
                list(self.api(port).stream())
            self.assertNotIn(SECRET, str(error.exception))

    def test_unavailable_traffic_and_negative_counter_are_rejected(self):
        for message in (Status(trafficAvailable=False, uplinkTotal=10), Status(trafficAvailable=True, uplinkTotal=-1)):
            with self.subTest(message=str(message)), local_server(status=frame(message.SerializeToString()) + trailer()) as (port, _):
                with self.assertRaises(MeteringError):
                    list(self.api(port).stream())

    def test_missing_multiple_and_zero_epochs_are_rejected(self):
        for payload in (trailer(), frame(StartedAt(startedAt=0).SerializeToString()) + trailer(), epoch_response()[:-len(trailer())] * 2 + trailer()):
            with self.subTest(payload=payload), local_server(epoch=payload) as (port, _):
                with self.assertRaises(MeteringError):
                    self.api(port).started_at()

    def test_multiple_status_messages_use_generated_protobuf_each_time(self):
        body = b"".join(frame(Status(trafficAvailable=True, uplinkTotal=UPLOAD+i, downlinkTotal=DOWNLOAD+i).SerializeToString()) for i in range(3)) + trailer()
        with local_server(status=body) as (port, _):
            samples = list(self.api(port).stream())
            self.assertEqual([sample.uplink for sample in samples], [UPLOAD, UPLOAD+1, UPLOAD+2])


if __name__ == "__main__":
    unittest.main()
