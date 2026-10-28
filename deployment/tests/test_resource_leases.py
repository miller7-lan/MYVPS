"""Root resource reuse retains revoked authorisation tombstones and fencing."""
import json
import unittest
import uuid
from unittest.mock import patch
from deployment.tests import test_helper as fixtures


class ResourceLeaseTests(unittest.TestCase):
    setUp = fixtures.HelperTests.setUp
    tearDown = fixtures.HelperTests.tearDown
    write = fixtures.HelperTests.write
    request = fixtures.HelperTests.request
    call = fixtures.HelperTests.call
    provision = fixtures.HelperTests.provision
    stage = fixtures.HelperTests.stage

    def ended(self):
        self.stage()
        self.call('activate', 3)
        self.call('revoke', 4)

    def new_credentials(self, lease):
        return dict(self.credentials, lease_id=lease, vless_uuid=str(uuid.uuid4()),
                    tuic_uuid=str(uuid.uuid4()), tuic_password='n'*43, api_secret='z'*48)

    def test_release_reuses_only_physical_slot_and_old_lease_cannot_return(self):
        self.ended()
        request = self.request('release', 5, params={'lease_id':self.worker_id})
        first = self.helper.dispatch(request, peer_uid=1001)
        self.assertTrue(first['ok'],first)
        self.assertEqual(first,self.helper.dispatch(request,peer_uid=1001))
        self.assertFalse((self.etc/'workers'/(self.worker_id+'.json')).exists())
        registry=json.loads(self.layout.registry.read_text())
        self.assertTrue(registry['retired_authorizations'][self.worker_id+':'+self.worker_id]['tombstoned'])
        denied=self.helper.dispatch(self.request('provision',6),peer_uid=1001)
        self.assertEqual(denied['error']['code'],'REVOKED')
        lease=str(uuid.uuid4());new=self.new_credentials(lease)
        self.call('provision',6,params=new)
        old_in_new_lease=dict(self.credentials,lease_id=lease)
        denied=self.helper.dispatch(self.request('stage',7,params=old_in_new_lease),peer_uid=1001)
        self.assertEqual(denied['error']['code'],'REVOKED')
        self.call('stage',7,params=new)
        denied=self.helper.dispatch(self.request('activate',8),peer_uid=1001)
        self.assertIn(denied['error']['code'],{'LEASE_MISMATCH','REVOKED'})
        self.call('activate',8,params=new)
        self.assertTrue(json.loads(self.layout.registry.read_text())['retired_authorizations'])

    def test_release_does_not_accept_wrong_lease_running_or_unconfirmed_stop(self):
        self.stage()
        result=self.helper.dispatch(self.request('release',3,params={'lease_id':self.worker_id}),peer_uid=1001)
        self.assertFalse(result['ok'])
        self.call('revoke',3)
        result=self.helper.dispatch(self.request('release',4,params={'lease_id':str(uuid.uuid4())}),peer_uid=1001)
        self.assertFalse(result['ok'])
        self.runner.states['dazzle-proxy@'+self.worker_id+'.service']=7777
        result=self.helper.dispatch(self.request('release',4,params={'lease_id':self.worker_id}),peer_uid=1001)
        self.assertFalse(result['ok'])

    def test_retired_credentials_are_rejected_even_with_a_different_lease_id(self):
        self.ended();self.call('release',5,params={'lease_id':self.worker_id})
        result=self.helper.dispatch(self.request('provision',6,params=dict(self.credentials,lease_id=str(uuid.uuid4()))),peer_uid=1001)
        self.assertEqual(result['error']['code'],'REVOKED')

    def test_revoke_before_provision_can_release_initial_and_reused_unbound_assignments(self):
        self.call('revoke',1)
        request=self.request('release',2,params={'lease_id':self.worker_id})
        first=self.helper.dispatch(request,peer_uid=1001)
        self.assertTrue(first['ok'],first)
        self.assertEqual(first,self.helper.dispatch(request,peer_uid=1001))
        denied=self.helper.dispatch(self.request('provision',3),peer_uid=1001)
        self.assertEqual(denied['error']['code'],'REVOKED')

        # A new application lease may also be revoked before root ever receives
        # its provision job. Each unused identity still gets its own tombstone.
        second=str(uuid.uuid4())
        self.call('revoke',3)
        self.call('release',4,params={'lease_id':second})
        registry=json.loads(self.layout.registry.read_text())
        for lease in (self.worker_id,second):
            self.assertTrue(registry['retired_authorizations'][self.worker_id+':'+lease]['tombstoned'])
            denied=self.helper.dispatch(self.request('provision',5,params=self.new_credentials(lease)),peer_uid=1001)
            self.assertEqual(denied['error']['code'],'REVOKED')
        stale=self.helper.dispatch(self.request('release',2,params={'lease_id':second}),peer_uid=1001)
        self.assertEqual(stale['error']['code'],'STALE_GENERATION')
        self.call('provision',5,params=self.new_credentials(str(uuid.uuid4())))

    def test_unbound_revocation_cannot_release_with_prior_material_or_a_running_process(self):
        self.call('revoke',1)
        for field,value in (('credentials',{}),('private_key','a'*43),('public_key','b'*43)):
            with self.subTest(field=field):
                registry=json.loads(self.layout.registry.read_text())
                registry['workers'][self.worker_id][field]=value
                self.write(self.layout.registry,registry)
                denied=self.helper.dispatch(self.request('release',2,params={'lease_id':self.worker_id}),peer_uid=1001)
                self.assertEqual(denied['error']['code'],'RELEASE_UNCONFIRMED')
                registry['workers'][self.worker_id].pop(field)
                self.write(self.layout.registry,registry)
        self.runner.states['dazzle-proxy@'+self.worker_id+'.service']=7777
        denied=self.helper.dispatch(self.request('release',2,params={'lease_id':self.worker_id}),peer_uid=1001)
        self.assertEqual(denied['error']['code'],'RELEASE_UNCONFIRMED')

    def test_first_assignment_can_use_an_independent_user_identity(self):
        lease=str(uuid.uuid4());new=self.new_credentials(lease)
        self.call('provision',1,params=new)
        self.call('stage',2,params=new)
        self.assertEqual(json.loads(self.layout.registry.read_text())['workers'][self.worker_id]['lease_id'],lease)

    def test_administrator_guard_proofs_require_separate_root_approval(self):
        self.layout.guard_proofs.mkdir(mode=0o750)
        self.write(self.etc/'admin-budget-guard.json',{'server_id':self.policy['server_id'],'worker_id':self.admin_id,'approved':True})
        with patch('deployment.helper.machine_boot_id',return_value=str(uuid.uuid4())):
            self.call('provision',1,worker=self.admin_id)
            self.call('stage',2,worker=self.admin_id)
        proof=json.loads((self.layout.guard_proofs/(self.admin_id+'.json')).read_text())
        self.assertEqual(proof['worker_id'],self.admin_id)
        self.assertEqual(proof['mode'],'staged')
