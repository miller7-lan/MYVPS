"""The local portal bridge never exposes the privileged management controller."""
import json
import hashlib
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
import uuid

from dazzle.portal_rpc import PortalExecutor, MAX_MESSAGE, dispatch
from dazzle.production_state import CORE_SHA256, ProductionStore
from test_authorization_fixtures import seed_legacy_user


class PortalSocketTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(); self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        self.socket_dir = root / "run"; self.socket_dir.mkdir(); self.socket_dir.chmod(0o2750)
        self.path = self.socket_dir / "agent.sock"
        self.policy = {"version": 2, "server_id": str(uuid.uuid4()), "server_endpoint": "8.8.8.8",
                       "agent_uid": max(os.geteuid(), 1), "portal_uid": max(os.geteuid(), 1) + 1,
                       "core_sha256": CORE_SHA256,
                       "workers": {str(uuid.uuid4()): {"role": "admin", "public_port": 24430, "api_port": 34430},
                                   str(uuid.uuid4()): {"role": "member", "public_port": 24431, "api_port": 34431}}}
        self.store = ProductionStore(root / "state", policy=self.policy, initialize=True)
        self.addCleanup(self.store.close)
        self.executor = PortalExecutor(self.store, self.path)
        self.executor.start(); self.addCleanup(self.executor.close)

    def query(self, request=None, raw=None):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(3)
        self.addCleanup(connection.close)
        connection.connect(str(self.path))
        payload = raw if raw is not None else json.dumps(request).encode() + b"\n"
        try:
            connection.sendall(payload); connection.shutdown(socket.SHUT_WR)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return b""
        body = bytearray()
        while True:
            try: part = connection.recv(65536)
            except ConnectionResetError: break
            if not part: break
            body.extend(part)
        return bytes(body)

    def envelope(self, operation="session.me", params=None):
        return {"version": 1, "request_id": str(uuid.uuid4()), "operation": operation,
                "params": params or {"session_token": "invalid"}, "peer_ip": "192.0.2.3"}

    def test_unapproved_peer_gets_no_response_even_for_valid_envelope(self):
        with patch("dazzle.portal_rpc.peer_uid", return_value=self.policy["portal_uid"] + 1):
            self.assertEqual(self.query(self.envelope()), b"")

    def test_approved_peer_cannot_pass_management_actions_or_identity_fields(self):
        with patch("dazzle.portal_rpc.peer_uid", return_value=self.policy["portal_uid"]):
            for operation in ("user.enable", "mail.configure", "registration.approve", "snapshot"):
                result = json.loads(self.query(self.envelope(operation)))
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"]["code"], "VALIDATION")
            request = self.envelope(); request["uid"] = self.policy["agent_uid"]
            self.assertEqual(json.loads(self.query(request))["error"]["code"], "VALIDATION")

    def test_large_or_incomplete_message_is_rejected_without_opening_operation(self):
        with patch("dazzle.portal_rpc.peer_uid", return_value=self.policy["portal_uid"]):
            self.assertEqual(self.query(raw=b"x" * (MAX_MESSAGE + 1) + b"\n"), b"")
            self.assertEqual(self.query(raw=b'{"version":1}'), b"")

    def test_socket_is_private_and_shutdown_removes_only_owned_socket(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o660)
        self.executor.close()
        self.assertFalse(self.path.exists())
        self.executor.server = self.executor.thread = None

    def test_world_accessible_runtime_directory_is_rejected(self):
        self.executor.close(); self.executor.server = self.executor.thread = None
        self.socket_dir.chmod(0o2777)
        with self.assertRaises(PermissionError):
            self.executor.start()
        self.assertFalse(self.path.exists())

    def test_readonly_socket_lookups_do_not_wait_for_existing_writer(self):
        self.store.conn.execute("BEGIN IMMEDIATE")
        self.store.set_meta("uncommitted_writer_fixture", True)
        try:
            with patch("dazzle.portal_rpc.peer_uid", return_value=self.policy["portal_uid"]):
                response = json.loads(self.query(self.envelope("subscription.fetch", {"token":"unknown-token-which-is-long-enough", "route":"config.yaml"})))
                self.assertTrue(response["ok"])
                self.assertEqual(response["data"]["status"],404)
                response = json.loads(self.query(self.envelope("session.me", {"session_token":"A"*43})))
                self.assertEqual(response["error"]["code"],"UNAUTHENTICATED")
            self.assertTrue(self.store.conn.in_transaction)
        finally:
            self.store.conn.rollback()

    def test_authenticated_account_renders_using_genuine_readonly_connection(self):
        from dazzle.store import timestamp, utcnow
        now = timestamp(utcnow())
        identifier, session, token = str(uuid.uuid4()), "B"*43, "C"*48
        self.store.conn.execute("INSERT INTO portal_accounts(id,email,nickname,status,email_verified_at,subscription_token,created_at,updated_at) VALUES(?,?,?,'pending',?,?,?,?)",
            (identifier,"readonly@example.test","Read-only",now,token,now,now))
        self.store.conn.execute("INSERT INTO portal_sessions VALUES(?,?,?,?,NULL)",
            (hashlib.sha256(session.encode()).hexdigest(),identifier,now,"2099-01-01T00:00:00Z"))
        with ProductionStore(self.store.state_dir, policy=self.policy, read_only=True) as reader:
            statements = []; reader.conn.set_trace_callback(statements.append)
            response = dispatch(reader,self.envelope("session.me", {"session_token":session}))
            self.assertTrue(response["ok"], response)
            self.assertEqual(response["data"]["account"]["id"],identifier)
            self.assertNotIn("subscriptions", response["data"])
            self.assertEqual(response["data"]["delivery"]["method"], "email")
            response = dispatch(reader,self.envelope("subscription.fetch", {"token":token, "route":"config.yaml"}))
            self.assertEqual(response["data"]["status"],403)
            self.assertEqual(reader.conn.total_changes,0)
            self.assertIn("BEGIN", statements)
            self.assertNotIn("BEGIN IMMEDIATE",statements)
            self.assertFalse(any(line.startswith(("INSERT","UPDATE","DELETE","CREATE","REPLACE")) for line in statements))

    def test_active_subscription_renderer_has_no_write_side_effects(self):
        import base64
        from dazzle.production import handle_request, process_one_job, accept_sample
        from dazzle.metering import MeterSample
        from dazzle.store import timestamp, utcnow
        from test_production import StrictHelper
        now = utcnow()
        def rpc(action,params):
            response=handle_request(self.store,{"api_version":1,"request_id":str(uuid.uuid4()),"action":action,
                "params":params,"server_id":self.store.server_id,"expected_revision":self.store.revision},now)
            self.assertTrue(response["ok"],response)
            return response["data"]
        user=seed_legacy_user(self.store,{"name":"Readonly rendering", "role":"member","quota_bytes":100000},now)["id"]
        helper=StrictHelper(self.policy,self.store)
        for _ in range(2):self.assertTrue(process_one_job(self.store,helper,now=now)["applied"])
        worker=self.store.worker(user)
        self.store.conn.execute("BEGIN IMMEDIATE")
        accept_sample(self.store,user,worker["observed_generation"],MeterSample("fixture-epoch",0,0,timestamp(now)),now)
        self.store.conn.commit()
        rpc("user.enable",{"user_id":user})
        self.assertTrue(process_one_job(self.store,helper,now=now)["applied"])
        token=self.store.get_credentials(user)["subscription_token"]
        with ProductionStore(self.store.state_dir,policy=self.policy,read_only=True) as reader:
            response=dispatch(reader,self.envelope("subscription.fetch",{"token":token,"route":"config.yaml"}),now=now)
            self.assertTrue(response["ok"],response)
            self.assertEqual(response["data"]["status"],200)
            profile=json.loads(base64.b64decode(response["data"]["body_b64"]))
            self.assertEqual(len(profile["proxies"]),2)
            self.assertEqual(reader.conn.total_changes,0)

    def test_subscription_lookup_is_anonymous_but_pending_management_is_not_available(self):
        with patch("dazzle.portal_rpc.peer_uid", return_value=self.policy["portal_uid"]):
            result = json.loads(self.query(self.envelope("subscription.fetch", {"token": "unknown-token-which-is-long-enough", "route": "config.yaml"})))
            self.assertTrue(result["ok"])
            self.assertEqual(result["data"]["status"], 404)
            self.assertEqual(result["data"]["body_b64"], "")


if __name__ == '__main__': unittest.main()
