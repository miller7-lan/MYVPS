"""Public link naming is optional; existing IP nodes and credentials are stable.

All state, mail payloads and proxy observations below are isolated fixtures. No
DNS, SMTP, certificate service or production host is contacted.
"""
import json
import tempfile
import unittest
from urllib.parse import urlsplit
import uuid

from dazzle import mail, registration
from dazzle.metering import MeterSample
from dazzle.portal_rpc import dispatch
from dazzle.production import accept_sample, handle_request, process_one_job, subscription_response
from dazzle.production_state import CORE_SHA256, ProductionStore, checked_hostname, public_origin
from dazzle.store import parse_time, timestamp
from test_authorization_fixtures import seed_legacy_user
from test_production import StrictHelper


class PublicHostnameTests(unittest.TestCase):
    hostname = "dazzle-test.duckdns.org"
    ip_origin = "https://8.8.8.8:9443"

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.now = parse_time("2026-11-01T08:19:00Z")
        self.admin, self.member = str(uuid.uuid4()), str(uuid.uuid4())
        self.policy = {
            "version": 1, "server_id": str(uuid.uuid4()), "server_endpoint": "8.8.8.8",
            "agent_uid": 1001, "core_sha256": CORE_SHA256,
            "workers": {
                self.admin: {"role": "admin", "public_port": 24430, "api_port": 34430},
                self.member: {"role": "member", "public_port": 24431, "api_port": 34431},
            },
        }
        self.store = ProductionStore(self.folder.name, policy=self.policy, initialize=True, now=self.now)
        self.addCleanup(self.store.close)
        self.helper = StrictHelper(self.policy, self.store)

    @property
    def hostname_origin(self):
        return "https://" + self.hostname + ":9443"

    def rpc(self, action, params, *, expected_revision=None, server_id=None):
        return handle_request(self.store, {
            "api_version": 1, "request_id": str(uuid.uuid4()), "action": action,
            "server_id": self.store.server_id if server_id is None else server_id,
            "expected_revision": self.store.revision if expected_revision is None else expected_revision,
            "params": params,
        }, self.now)

    def hostname_update(self, value):
        return self.rpc("settings.update", {"public_hostname": value})

    def export(self, user, format_name="mihomo"):
        result = self.rpc("user.export", {"user_id": user, "format": format_name})
        self.assertTrue(result["ok"], result)
        return result["data"]

    def sample_origin(self, user):
        worker = self.store.worker(user)
        self.store.conn.execute("BEGIN IMMEDIATE")
        try:
            accept_sample(self.store, user, worker["observed_generation"],
                          MeterSample("hostname-test-epoch-" + str(worker["observed_generation"]),
                                      0, 0, timestamp(self.now)), self.now)
            self.store.conn.commit()
        except BaseException:
            self.store.conn.rollback()
            raise

    def running_member(self):
        user = seed_legacy_user(self.store, {
            "name": "Hostname fixture", "role": "member", "quota_bytes": 100_000_000_000,
        }, self.now)["id"]
        for _ in range(2):
            self.assertTrue(process_one_job(self.store, self.helper, now=self.now)["applied"])
        self.sample_origin(user)
        self.assertTrue(self.rpc("user.enable", {"user_id": user})["ok"])
        self.assertTrue(process_one_job(self.store, self.helper, now=self.now)["applied"])
        self.sample_origin(user)
        return user

    def test_default_origin_and_registration_snapshot_keep_policy_ip(self):
        self.assertIsNone(self.store.get_setting("public_hostname"))
        self.assertEqual(public_origin(self.store), self.ip_origin)
        snapshot = registration.snapshot(self.store, self.now)
        self.assertEqual(snapshot["portal_url"], self.ip_origin + "/portal/")
        self.assertIsNone(snapshot["public_hostname"])

    def test_checked_hostname_accepts_lowercase_dns_labels_and_length_boundaries(self):
        for name in (self.hostname, "a.bc", "one-two.example.test", "xn--bcher-kva.example",
                     "a" * 63 + ".example", ".".join(["a" * 63] * 3 + ["b" * 61])):
            with self.subTest(name=name):
                self.assertEqual(checked_hostname(name), name)

    def test_checked_hostname_rejects_ip_url_authority_and_malformed_names(self):
        invalid = (None, False, 0, [], {}, "", "8.8.8.8", "2001:db8::1", "localhost",
                   "Dazzle.example", "https://dazzle.example", "dazzle.example:9443",
                   "user@dazzle.example", "dazzle.example/path", "dazzle.example?x=1",
                   "dazzle.example#x", "*.example.test", ".example.test", "example.test.",
                   "bad..example", "-bad.example", "bad-.example", "bad_label.example",
                   "dazzle.example\n", " dazzle.example", "bücher.example", "a" * 64 + ".example",
                   ".".join(["a" * 63] * 3 + ["b" * 62]))
        for name in invalid:
            with self.subTest(name=repr(name)):
                with self.assertRaises(ValueError):
                    checked_hostname(name)

    def test_management_setting_selects_hostname_for_snapshot_and_links(self):
        result = self.hostname_update(self.hostname)
        self.assertTrue(result["ok"], result)
        self.assertEqual(public_origin(self.store), self.hostname_origin)
        registered = self.rpc("registration.list", {})
        self.assertTrue(registered["ok"], registered)
        info = registered["data"]["registration"]
        self.assertEqual(info["portal_url"], self.hostname_origin + "/portal/")
        self.assertEqual(info["public_hostname"], self.hostname)

    def test_management_rejects_invalid_hostname_without_replacing_existing_value(self):
        self.assertTrue(self.hostname_update(self.hostname)["ok"])
        for name in ("8.8.8.8", "https://dazzle.example", "upper.EXAMPLE", "bad..example",
                     "bad.example:9443", "bad.example/path", "bad.example\n", 1, True, ["x"]):
            with self.subTest(name=repr(name)):
                revision = self.store.revision
                result = self.hostname_update(name)
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["error"]["code"], "VALIDATION")
                self.assertEqual(self.store.get_setting("public_hostname"), self.hostname)
                self.assertEqual(self.store.revision, revision)

    def test_management_rejects_falsey_nonstring_hostname_values(self):
        for name in (False, 0, 0.0, [], {}):
            with self.subTest(name=repr(name)):
                self.assertTrue(self.hostname_update(self.hostname)["ok"])
                revision = self.store.revision
                result = self.hostname_update(name)
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["error"]["code"], "VALIDATION")
                self.assertEqual(self.store.get_setting("public_hostname"), self.hostname)
                self.assertEqual(self.store.revision, revision)

    def test_null_and_empty_text_clear_only_the_optional_hostname(self):
        user = self.running_member()
        credentials, worker = self.store.get_credentials(user), self.store.worker(user)
        for name in (None, ""):
            with self.subTest(name=name):
                self.assertTrue(self.hostname_update(self.hostname)["ok"])
                self.assertTrue(self.hostname_update(name)["ok"])
                self.assertIsNone(self.store.get_setting("public_hostname"))
                self.assertEqual(public_origin(self.store), self.ip_origin)
                self.assertTrue(self.export(user)["subscription_url"].startswith(self.ip_origin + "/"))
                self.assertEqual(self.store.get_credentials(user), credentials)
                self.assertEqual(self.store.worker(user), worker)

    def test_hostname_updates_require_current_revision_and_registered_server(self):
        result = self.rpc("settings.update", {"public_hostname": self.hostname}, expected_revision=-1)
        self.assertEqual(result["error"]["code"], "REVISION_CONFLICT")
        result = self.rpc("settings.update", {"public_hostname": self.hostname}, server_id=str(uuid.uuid4()))
        self.assertEqual(result["error"]["code"], "SERVER_ID_MISMATCH")
        self.assertIsNone(self.store.get_setting("public_hostname"))

    def test_combined_settings_validation_is_atomic_for_hostname_and_registration(self):
        self.assertFalse(self.store.get_setting("registration_enabled"))
        revision = self.store.revision
        result = self.rpc("settings.update", {
            "public_hostname": self.hostname, "registration_enabled": True, "time": "25:00",
        })
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["error"]["code"], "VALIDATION")
        self.assertIsNone(self.store.get_setting("public_hostname"))
        self.assertFalse(self.store.get_setting("registration_enabled"))
        self.assertEqual(self.store.revision, revision)

    def test_hostname_never_rotates_tokens_changes_worker_or_rewrites_ip_node_content(self):
        user = self.running_member()
        credentials, worker = self.store.get_credentials(user), self.store.worker(user)
        token = credentials["subscription_token"]
        original = {route: subscription_response(self.store, token, route, self.now)
                    for route in ("config.yaml", "config.conf", "nodes.txt")}
        self.assertTrue(all(item["status"] == 200 for item in original.values()))
        old_links = self.export(user)
        self.assertTrue(self.hostname_update(self.hostname)["ok"])
        self.assertEqual(self.store.get_credentials(user), credentials)
        self.assertEqual(self.store.worker(user), worker)
        self.assertEqual(self.store.policy["server_endpoint"], "8.8.8.8")
        for route, response in original.items():
            with self.subTest(route=route):
                self.assertEqual(subscription_response(self.store, token, route, self.now), response)
                old_url = old_links["nodes_url"] if route == "nodes.txt" else self.ip_origin + "/" + token + "/" + route
                self.assertEqual(urlsplit(old_url).hostname, "8.8.8.8")
                self.assertEqual(urlsplit(old_url).path, "/" + token + "/" + route)
        profile = json.loads(self.export(user)["content"])
        self.assertTrue(profile["proxies"])
        self.assertTrue(all(proxy["server"] == "8.8.8.8" for proxy in profile["proxies"]))

    def test_user_export_and_registration_links_choose_same_origin_for_each_format(self):
        user = self.running_member()
        token = self.store.get_credentials(user)["subscription_token"]
        account = {"subscription_token": token, "status": "active"}
        for name, origin in ((None, self.ip_origin), (self.hostname, self.hostname_origin)):
            with self.subTest(name=name):
                self.assertTrue(self.hostname_update(name)["ok"])
                links = registration._links(self.store, account)
                self.assertEqual(links, {"clash": origin + "/" + token + "/config.yaml",
                                         "shadowrocket": origin + "/" + token + "/nodes.txt"})
                for format_name in ("uris", "shadowrocket", "mihomo"):
                    exported = self.export(user, format_name)
                    self.assertEqual(exported["nodes_url"], links["shadowrocket"])
                    self.assertEqual(exported["config_url"], origin + "/" + token + "/config.conf")
                    self.assertEqual(exported["subscription_url"], links["clash"] if format_name == "mihomo" else links["shadowrocket"])
                    self.assertNotIn(self.hostname, exported["content"])

    def test_subscription_email_uses_selected_hostname_without_public_payload_leak(self):
        user = self.running_member()
        self.store.conn.execute("UPDATE users SET email=?,email_verified=1 WHERE id=?", ("member@example.test", user))
        result = self.rpc("mail.configure", {
            "host": "smtp.example.test", "port": 465, "security": "ssl", "username": "sender@example.test",
            "sender": "sender@example.test", "admin_email": "admin@example.test", "secret": "test-only-smtp-secret",
        })
        self.assertTrue(result["ok"], result)
        self.assertTrue(self.hostname_update(self.hostname)["ok"])
        result = self.rpc("user.subscription_email", {"user_id": user})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["data"]["mail"]["state"], "queued")
        row = self.store.conn.execute(
            "SELECT o.body,p.body AS private_body FROM mail_outbox o JOIN mail_private_payload p ON p.outbox_id=o.id "
            "WHERE o.kind='subscription_resend'").fetchone()
        self.assertIsNotNone(row)
        links = self.export(user)
        for key in ("nodes_url", "subscription_url"):
            self.assertIn(links[key], row["private_body"])
            self.assertNotIn(links[key], row["body"])
            self.assertNotIn(links[key], json.dumps(mail.snapshot_mail(self.store)))
        self.assertNotIn(self.ip_origin, row["private_body"])

    def test_public_portal_operations_cannot_set_public_hostname(self):
        self.assertTrue(self.hostname_update(self.hostname)["ok"])
        attempts = {operation: {**{key: "fixture" for key in required}, "public_hostname": "attacker.example"}
                    for operation, (required, _) in registration.PUBLIC_PARAMETERS.items()}
        attempts["settings.update"] = {"public_hostname": "attacker.example"}
        for operation, params in attempts.items():
            with self.subTest(operation=operation):
                result = dispatch(self.store, {
                    "version": 1, "request_id": str(uuid.uuid4()), "operation": operation,
                    "params": params, "peer_ip": "192.0.2.9",
                }, now=self.now)
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["error"]["code"], "VALIDATION")
                self.assertEqual(self.store.get_setting("public_hostname"), self.hostname)


if __name__ == "__main__":
    unittest.main()
