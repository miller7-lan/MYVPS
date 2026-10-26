"""Read-only adoption review. No systemd or production state calls here."""
import copy
from pathlib import Path
import unittest
import uuid

from deployment import handoff
from deployment.helper import CORE_SHA256

ROOT=Path(__file__).resolve().parents[1]


class HandoffReviewTests(unittest.TestCase):
    def setUp(self):
        self.identifier=str(uuid.uuid4())
        self.member=(ROOT/'systemd/dazzle-proxy@.service').read_text()
        self.writer=(ROOT/'systemd/dazzle-vps-agent.service').read_text()
        self.before={'pid':101,'active_state':'active','restarts':0,'binds_to':[handoff.OLD_WRITER]}

    def test_complete_override_changes_only_dependencies_and_preserves_execution_limits(self):
        result=handoff.render_existing_member(self.member,self.identifier)
        self.assertEqual(self.member.split('[Service]',1)[1],result.split('[Service]',1)[1])
        self.assertNotIn('BindsTo=',result)
        self.assertIn('\nWants=network-online.target '+handoff.guard_name(self.identifier)+'\n',result)
        self.assertIn('\nAfter=network-online.target '+handoff.guard_name(self.identifier)+'\n',result)
        self.assertNotIn(handoff.OLD_WRITER,result)

    def test_unknown_member_dependency_or_non_uuid_cannot_be_retargeted(self):
        with self.assertRaises(ValueError):handoff.render_existing_member(self.member.replace(handoff.OLD_WRITER,'unknown.service'),self.identifier)
        with self.assertRaises(Exception):handoff.render_existing_member(self.member,'../other')

    def test_pid_restart_count_and_actual_bindings_must_all_remain_proven(self):
        correct=dict(self.before,binds_to=[],wants=['network-online.target',handoff.guard_name(self.identifier)])
        handoff.verify_member_observation(self.before,correct,self.identifier)
        for changed in ({'pid':102},{'restarts':1},{'active_state':'inactive'},{'binds_to':[handoff.OLD_WRITER]},
                        {'binds_to':[handoff.guard_name(self.identifier)]},{'wants':['network-online.target']}):
            with self.subTest(changed=changed),self.assertRaises(ValueError):handoff.verify_member_observation(self.before,correct|changed,self.identifier)

    def test_old_writer_fallback_pins_immutable_source_and_v1_snapshot(self):
        result=handoff.render_old_writer_fallback(self.writer,'a'*24)
        self.assertIn('/opt/dazzle-vps/releases/'+'a'*24+'/venv/bin/python',result)
        self.assertIn('--policy '+handoff.OLD_POLICY_SNAPSHOT,result)
        self.assertNotIn('/current/',result)
        before=[line for line in self.writer.splitlines() if not line.startswith('ExecStart=')]
        after=[line for line in result.splitlines() if not line.startswith('ExecStart=')]
        self.assertEqual(before,after)
        with self.assertRaises(ValueError):handoff.render_old_writer_fallback(self.writer,'../../current')

    def environment(self):
        return {'version':1,'legacy_services':{name:{'active_state':'inactive','pid':0,'load_state':'not-found'} for name in handoff.LEGACY_UNITS},
                'legacy_files':{name:{'present':False,'sha256':None} for name in handoff.LEGACY_FILES},
                'core_copy':{'present':True,'sha256':CORE_SHA256},'old_writer':{'active_state':'active','pid':7},
                'workers':{'admin':{'role':'admin','active_state':'active','pid':8}}}

    def test_user_retired_legacy_is_preserved_as_absent_without_fabricated_healthy_state(self):
        evidence=self.environment();original=copy.deepcopy(evidence)
        confirmation={'administrator_confirmed':True,'preserve_absence':True,'evidence':'administrator reports prior cleanup; absence observed'}
        result=handoff.validate_environment(evidence,confirmation)
        self.assertEqual(evidence,original)
        self.assertEqual(result['legacy_mode'],'administrator_retired');self.assertFalse(result['restore_legacy'])

    def test_unconfirmed_legacy_absence_and_missing_pinned_new_core_are_not_bypassed(self):
        with self.assertRaises(ValueError):handoff.validate_environment(self.environment())
        evidence=self.environment();evidence['core_copy']={'present':False,'sha256':None}
        with self.assertRaises(ValueError):handoff.validate_environment(evidence,{'administrator_confirmed':True,'preserve_absence':True,'evidence':'approved prior retirement'})

    def test_guard_and_portal_have_no_legacy_writer_dependency_or_database_write_grant(self):
        guard=(ROOT/'portal-systemd/meter-guard@.service').read_text()
        self.assertNotIn('BindsTo=',guard);self.assertNotIn('Requires=',guard)
        self.assertIn('ReadOnlyPaths=/var/lib/dazzle-vps',guard);self.assertNotIn('ReadWritePaths=/var/lib/dazzle-vps',guard)
        self.assertIn('ExecStart=/opt/dazzle-vps/releases/@RELEASE_ID@/venv/bin/python',guard);self.assertNotIn('/current/',guard)
        writer=(ROOT/'portal-systemd/writer@.service').read_text()
        self.assertIn('ExecStart=/opt/dazzle-vps/releases/%i/venv/bin/python -I -m dazzle.production',writer)
        self.assertIn(' agent --standby --allow-no-core-recovery\n',writer);self.assertNotIn('/current/',writer)
        self.assertEqual(handoff.writer_unit('a'*24),'dazzle-vps-writer@'+'a'*24+'.service')
        with self.assertRaises(ValueError):handoff.writer_unit('../current')
        portal=(ROOT/'portal-systemd/subscription.service').read_text()
        # A future writer handoff must never stop 9443; the portal answers 503 meanwhile.
        self.assertNotIn('Requires=',portal);self.assertNotIn('dazzle-vps-agent',portal);self.assertNotIn('dazzle-vps-writer',portal)
        self.assertIn('BindReadOnlyPaths=/etc/dazzle-vps/web-tls:/run/dazzle-vps-web-tls',portal)
        self.assertIn('--cert /run/dazzle-vps-web-tls/cert.pem',portal)
        self.assertNotIn('SupplementaryGroups=dazzle-vps',portal)

    def test_managed_certificate_template_resets_only_path_settings_not_dependencies(self):
        template=(ROOT/'portal-systemd/managed-certsync.conf').read_text()
        self.assertIn('--managed-certbot-source',template)
        self.assertIn('ReadOnlyPaths=\n',template)
        self.assertNotIn('/etc/s-box',template)

