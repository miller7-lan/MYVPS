"""Authoritative budget adoption gates, independent of the App's disabled UI."""
import tempfile
import unittest
import uuid

from dazzle import budget, registration
from dazzle.production import handle_request
from dazzle.production_state import CORE_SHA256, ProductionStore
from dazzle.store import parse_time, timestamp
from test_authorization_fixtures import confirm_test_budget, seed_legacy_user

GB = budget.GB


class AdmissionBudgetTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.now = parse_time("2026-11-01T08:19:00Z")
        identifiers = [str(uuid.uuid4()) for _ in range(3)]
        self.policy = {"version": 2, "server_id": str(uuid.uuid4()), "server_endpoint": "8.8.8.8",
                       "agent_uid": 995, "portal_uid": 994, "core_sha256": CORE_SHA256,
                       "workers": {identifier: {"role":"admin" if index == 0 else "member",
                                  "public_port":24430+index,"api_port":34430+index}
                                   for index, identifier in enumerate(identifiers)}}
        self.store = ProductionStore(self.folder.name, policy=self.policy, initialize=True, now=self.now)
        self.addCleanup(self.store.close)

    def rpc(self, action, params=None):
        return handle_request(self.store, {"api_version":1,"request_id":str(uuid.uuid4()),"action":action,
            "server_id":self.store.server_id,"expected_revision":self.store.revision,"params":params or {}},self.now)

    def state(self):
        tables = ("users","credentials","production_jobs","resource_leases","operations","requests")
        return (self.store.revision, {table:[tuple(row) for row in self.store.conn.execute("SELECT * FROM "+table)] for table in tables})

    def test_unconfirmed_new_user_rpc_is_denied_without_partial_allocation(self):
        before = self.state()
        response = self.rpc("user.add", {"name":"Unbudgeted", "quota_bytes":100*GB})
        self.assertEqual(response["error"]["code"], "BUDGET_NOT_CONFIGURED")
        self.assertEqual(self.state(), before)

    def test_unconfirmed_approval_does_not_allocate_or_send_approval_mail(self):
        registration.ensure_schema(self.store)
        account = str(uuid.uuid4())
        self.store.conn.execute("INSERT INTO portal_accounts(id,email,nickname,status,email_verified_at,subscription_token,created_at,updated_at) VALUES(?,?,?,'pending',?,?,?,?)",
            (account,"friend@example.test","Friend",timestamp(self.now),"private-test-token",timestamp(self.now),timestamp(self.now)))
        before = self.state()
        response = self.rpc("registration.approve", {"account_id":account})
        self.assertEqual(response["error"]["code"], "BUDGET_NOT_CONFIGURED")
        self.assertEqual(self.state(), before)
        self.assertEqual(self.store.conn.execute("SELECT status FROM portal_accounts WHERE id=?",(account,)).fetchone()[0],"pending")
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox").fetchone()[0],0)

    def test_unconfirmed_topup_quota_increase_and_unlimited_grant_are_denied(self):
        user = seed_legacy_user(self.store,{"name":"Existing", "quota_bytes":100*GB},self.now)
        for action, fields in (("user.topup",{"bytes":GB}), ("user.update",{"quota_bytes":101*GB}),
                               ("user.update",{"unlimited":True})):
            with self.subTest(action=action,fields=fields):
                before = self.state()
                response = self.rpc(action,{"user_id":user["id"],**fields})
                self.assertEqual(response["error"]["code"],"BUDGET_NOT_CONFIGURED")
                self.assertEqual(self.state(),before)

    def test_existing_allowance_can_be_lowered_without_changing_credentials_or_usage(self):
        user = seed_legacy_user(self.store,{"name":"Existing", "quota_bytes":100*GB},self.now)
        self.store.conn.execute("UPDATE users SET used_upload=?,used_download=? WHERE id=?",(20*GB,10*GB,user["id"]))
        credentials = self.store.get_credentials(user["id"])
        response = self.rpc("user.update",{"user_id":user["id"],"quota_bytes":50*GB})
        self.assertTrue(response["ok"],response)
        current = self.store.get_user(user["id"])
        self.assertEqual((current["quota_bytes"],current["used_upload"],current["used_download"]),(50*GB,20*GB,10*GB))
        self.assertEqual(self.store.get_credentials(user["id"]),credentials)
        rejected = self.rpc("user.update",{"user_id":user["id"],"quota_bytes":29*GB})
        self.assertEqual(rejected["error"]["code"],"QUOTA_BELOW_USED")

    def test_legacy_unlimited_member_can_be_made_finite_before_budget_adoption(self):
        user = seed_legacy_user(self.store,{"name":"Legacy unlimited", "quota_bytes":100*GB,"unlimited":True},self.now)
        response = self.rpc("user.update",{"user_id":user["id"],"quota_bytes":50*GB,"unlimited":False})
        self.assertTrue(response["ok"],response)
        current = self.store.get_user(user["id"])
        self.assertEqual((current["quota_bytes"],current["unlimited"]),(50*GB,0))
        confirm_test_budget(self.store,self.now,total_gb=100)
        allowed = self.rpc("user.add",{"name":"Budgeted new user","quota_bytes":50*GB})
        self.assertTrue(allowed["ok"],allowed)
        denied = self.rpc("user.topup",{"user_id":user["id"],"bytes":GB})
        self.assertEqual(denied["error"]["code"],"BUDGET_EXCEEDED")

    def test_unconfirmed_budget_does_not_block_existing_enable_or_metadata_change(self):
        user = seed_legacy_user(self.store,{"name":"Existing", "quota_bytes":100*GB},self.now)
        for action, params in (("user.update",{"name":"Existing renamed"}), ("user.enable",{}), ("user.disable",{})):
            response = self.rpc(action,{"user_id":user["id"],**params})
            self.assertTrue(response["ok"],response)
        self.assertFalse(budget.configured(self.store))

    def test_normal_refresh_does_not_wait_for_budget_adoption_or_clear_manual_pause(self):
        from dazzle.collector import tick
        user = seed_legacy_user(self.store,{"name":"Existing", "quota_bytes":100*GB},self.now)
        self.store.conn.execute("UPDATE users SET used_upload=?,topup_bytes=?,reasons_json='[\"quota_exceeded\"]' WHERE id=?",
                                (20*GB,5*GB,user["id"]))
        credentials = self.store.get_credentials(user["id"])
        before_cycle = self.store.get_meta("current_cycle_id")
        self.now = parse_time("2026-11-24T08:19:01Z")
        tick(self.store,self.now)
        current = self.store.get_user(user["id"])
        self.assertNotEqual(self.store.get_meta("current_cycle_id"),before_cycle)
        self.assertEqual((current["used_upload"],current["used_download"],current["topup_bytes"]),(0,0,0))
        self.assertEqual(current["quota_bytes"],100*GB)
        self.assertTrue(current["manual_disabled"])
        self.assertEqual(self.store.get_credentials(user["id"]),credentials)
        self.assertFalse(budget.configured(self.store))
