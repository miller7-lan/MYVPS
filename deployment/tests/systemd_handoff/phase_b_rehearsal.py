"""Real systemd Phase B and administrator guard executors in a disposable host.

Reuses the guarded Phase A fixture setup, completes the actual Phase A success
path without its later destructive watchdog experiment, then exercises Phase B.
Only the dazzle/Core/TLS processes are declared stand-ins; executors, templates,
root helper, permissions, process identities, locks and TCP sessions are real.
"""
from __future__ import annotations
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import time
import uuid

from rehearsal import Rehearsal, HERE, REPOSITORY, OWNED_PATHS, ACCOUNTS, GROUPS, run, show, wait_for, install
from deployment.coordinator import LAUNCHER
from deployment.installer import canonical, sha256
from deployment import admin_budget, expansion


class PhaseBRehearsal(Rehearsal):
    def __init__(self,scenario):
        super().__init__('success')
        self.phase_b_scenario=scenario

    def module(self,module,*arguments,timeout=300):
        python='/opt/dazzle-vps/releases/'+self.new_release+'/venv/bin/python'
        result=run(python,'-I','-m',module,*arguments,check=False,timeout=timeout)
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise AssertionError('module printed no JSON: '+module+' '+result.stderr[-2000:]) from None

    def setup(self):
        super().setup()
        _,phase_a=super().execute()
        assert phase_a['status']=='handoff_complete',phase_a
        self.assert_preserved()
        self.phase_a_release=self.new_release
        self.phase_a_writer='dazzle-vps-writer@'+self.phase_a_release+'.service'
        self.phase_a_pid=show(self.phase_a_writer,'MainPID')['MainPID']
        self.member_guard='dazzle-vps-meter-guard@'+self.member+'.service'
        self.guard_before=show(self.member_guard,'MainPID','InvocationID','NRestarts')
        self.phase_a_usage={user['id']:user['used_upload']+user['used_download'] for user in self.facts()['users']}
        self.core_config_digests={identifier:sha256(Path('/etc/dazzle-vps/workers/'+identifier+'.json').read_bytes())
                                  for identifier in (self.admin,self.member)}
        # Deliberately self-signed only inside this disposable container. The real
        # portal unit's readonly bind mount and low-privilege account are retained.
        run('/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=rehearsal.local',
            '-addext','subjectAltName=IP:192.0.2.10','-keyout','/etc/dazzle-vps/tls/key.pem','-out','/etc/dazzle-vps/tls/cert.pem')
        for name in ('cert.pem','key.pem'):
            os.chown('/etc/dazzle-vps/tls/'+name,0,self.vps)
            os.chmod('/etc/dazzle-vps/tls/'+name,0o640)
        install('/etc/systemd/system/dazzle-vps-certsync.service',(
            '[Unit]\nDescription=Disposable test certificate copier\n[Service]\nType=oneshot\n'
            'ExecStart=/usr/bin/python3 '+str(HERE/'phase_b_certsync.py')+'\n').encode(),0o644)
        install('/etc/systemd/system/dazzle-vps-subscription.service',
                (REPOSITORY/'deployment/systemd/dazzle-vps-subscription.service').read_bytes(),0o644)
        run('/usr/bin/systemctl','daemon-reload')
        run('/usr/bin/systemctl','enable','dazzle-vps-subscription.service')
        run('/usr/bin/systemctl','start','dazzle-vps-subscription.service')
        self.new_release=self.release('phase-b',manifest=True)
        approval={'version':1,'operation':expansion.ACCOUNT_OPERATION,'approved':True,'approval_id':str(uuid.uuid4()),'account':'dazzle-web'}
        install(self.private/'account-approval.json',json.dumps(approval).encode(),0o600)
        account=self.module('deployment.expansion','--create-account','--approval',str(self.private/'account-approval.json'))
        assert account.get('account')=='dazzle-web',account
        self.portal_before=show('dazzle-vps-subscription.service','MainPID','InvocationID','NRestarts')

    def assert_preserved(self):
        assert {role:show(self.unit(role),'MainPID','InvocationID','NRestarts') for role in ('admin','member')}==self.before
        assert self.client.error is None and self.client.pids=={int(self.before['member']['MainPID'])},(self.client.error,self.client.pids)
        assert Path('/usr/local/bin/dazzle-vps-control').read_bytes()==LAUNCHER
        assert self.facts()['incidents_total']==0,'metering gap recorded'

    def execute_expansion(self):
        fault=self.phase_b_scenario if self.phase_b_scenario in {'fail-takeover','hang-takeover','standby-never-ready'} else ''
        install('/etc/dazzle-vps/fixture-mode',json.dumps({'release':'phase-b','mode':fault}).encode(),0o644)
        preview=self.module('deployment.expansion','--preview','--new-release-id',self.new_release)
        plan=preview.get('plan') or {}
        if not plan:
            # Only fixture values exist here; expose the actual exception that
            # the safe production CLI correctly hides from ordinary output.
            expansion.build_expansion_plan(expansion.ExpansionHost(),expansion.Layout(),new_release_id=self.new_release)
        assert plan.get('ready_for_approval'),preview
        approval={'version':1,'operation':expansion.OPERATION,'approved':True,'approval_id':str(uuid.uuid4()),
                  'plan_sha256':sha256(canonical(plan)),'acknowledgements':{name:True for name in expansion.ACKNOWLEDGEMENTS}}
        install(self.private/'phase-b-plan.json',json.dumps(plan).encode(),0o600)
        install(self.private/'phase-b-approval.json',json.dumps(approval).encode(),0o600)
        result=self.module('deployment.expansion','--apply','--plan',str(self.private/'phase-b-plan.json'),'--approval',str(self.private/'phase-b-approval.json'))
        return plan,result

    def verify_expansion(self,plan,result):
        self.assert_preserved()
        assert show(self.member_guard,'MainPID','InvocationID','NRestarts')==self.guard_before
        assert show(self.unit('member'),'BindsTo')['BindsTo']==self.member_guard
        policy=Path('/etc/dazzle-vps/policy.json')
        # This real permission assertion catches a root:root restoration even if
        # the root executor itself can still read the old policy.
        info=policy.stat()
        assert info.st_uid==0 and info.st_gid==self.vps and stat.S_IMODE(info.st_mode)==0o640
        read=__import__('subprocess').run(['/usr/bin/python3','-c','from pathlib import Path; Path("/etc/dazzle-vps/policy.json").read_bytes()'],
            user=self.agent.pw_uid,group=self.agent.pw_gid,extra_groups=[self.vps],capture_output=True)
        assert read.returncode==0,read.stderr.decode()
        if self.phase_b_scenario in {'fail-takeover','hang-takeover'}:
            assert result['status']=='fallback_complete_members_preserved',result
            assert result['fallback']['within_sample_deadline'],result
            assert json.loads(policy.read_text())['version']==1
            assert os.readlink('/opt/dazzle-vps/current').endswith(self.phase_a_release)
            assert show(self.phase_a_writer,'ActiveState')['ActiveState']=='active'
            assert show('dazzle-vps-subscription.service','MainPID','InvocationID','NRestarts')==self.portal_before
        elif self.phase_b_scenario=='standby-never-ready':
            assert result['status']=='aborted_no_core_or_writer_changed',result
            assert show(self.phase_a_writer,'MainPID')['MainPID']==self.phase_a_pid
            assert json.loads(policy.read_text())['version']==1
            assert os.readlink('/opt/dazzle-vps/current').endswith(self.phase_a_release)
        else:
            assert result['status']=='handoff_complete',result
            assert result['portal']=='portal_running',result
            assert json.loads(policy.read_text())['version']==2
            assert os.readlink('/opt/dazzle-vps/current').endswith(self.new_release)
            probes=Path('/var/lib/dazzle-vps/fixture-portal-probes')
            assert probes.exists() and len(probes.read_text().splitlines())>=1
            host=expansion.ExpansionHost()
            assert host.https_status(9443,'/portal/')==200
            assert host.https_status(9443,'/'+'Z'*32+'/nodes.txt')==404
            expected=pwd.getpwnam('dazzle-web').pw_uid
            portal_pid=int(show('dazzle-vps-subscription.service','MainPID')['MainPID'])
            assert host.listeners(9443)==[(portal_pid,expected)]
        facts=self.facts()
        assert all(user['trusted_sample'] and user['meter_state']=='trusted' for user in facts['users'])
        assert facts.get('registration_enabled') is False and facts.get('registration_state_source')=='settings'
        assert all(user['used_upload']+user['used_download']>=self.phase_a_usage[user['id']] for user in facts['users'])
        assert {identifier:sha256(Path('/etc/dazzle-vps/workers/'+identifier+'.json').read_bytes())
                for identifier in (self.admin,self.member)}==self.core_config_digests
        current=Path('/opt/dazzle-vps/current').resolve().name
        writer_pid=int(show('dazzle-vps-writer@'+current+'.service','MainPID')['MainPID'])
        assert expansion.ExpansionHost().lock_holders()==[{'pid':writer_pid,'mode':'WRITE'}]
        return {'status':result['status'],'core_pids_preserved':True,'member_tcp_preserved':True,'guard_process_preserved':True,
                'policy_group_preserved':True,'no_metering_gap':True,'single_writer_lock_proven':True,
                'usage_monotonic':True,'registration_closed_verified':True,'core_config_digests_preserved':True,'measurements':plan['measurements'],
                'takeover':result.get('takeover'),'fallback':result.get('fallback'),'portal':result.get('portal')}

    def execute_admin(self):
        fault='budget-rejected' if self.phase_b_scenario=='admin-budget-rejected' else ''
        install('/etc/dazzle-vps/fixture-mode',json.dumps({'release':'phase-b','mode':fault}).encode(),0o644)
        preview=self.module('deployment.admin_budget','--preview','--total-gb','500','--margin-gb','0','--pool-user',self.member,
                            '--evidence','isolated administrator budget rehearsal')
        plan=preview.get('plan') or {}
        assert plan.get('ready_for_approval'),preview
        approval={'version':1,'operation':admin_budget.OPERATION,'approved':True,'approval_id':str(uuid.uuid4()),
                  'plan_sha256':sha256(canonical(plan)),'acknowledgements':{name:True for name in admin_budget.ACKNOWLEDGEMENTS}}
        install(self.private/'admin-plan.json',json.dumps(plan).encode(),0o600)
        install(self.private/'admin-approval.json',json.dumps(approval).encode(),0o600)
        result=self.module('deployment.admin_budget','--apply','--plan',str(self.private/'admin-plan.json'),
                           '--approval',str(self.private/'admin-approval.json'))
        self.assert_preserved()
        admin_unit=self.unit('admin')
        guard='dazzle-vps-meter-guard@'+self.admin+'.service'
        if fault:
            assert result['status']=='aborted_administrator_unchanged',result
            assert not Path('/etc/systemd/system/'+admin_unit).exists()
            assert not Path('/etc/dazzle-vps/admin-budget-guard.json').exists()
            assert show(admin_unit,'BindsTo')['BindsTo']==''
            assert show(guard,'ActiveState')['ActiveState'] in {'inactive','failed'}
            time.sleep(65)
            self.assert_preserved()
        else:
            assert result['status']=='budget_guard_complete',result
            assert show(admin_unit,'BindsTo')['BindsTo']==guard
            assert show(guard,'ActiveState')['ActiveState']=='active'
            assert all(item['ok'] for item in result['pool'])
        query={'api_version':1,'request_id':str(uuid.uuid4()),'server_id':self.server,'action':'snapshot','params':{}}
        python='/opt/dazzle-vps/releases/'+self.new_release+'/venv/bin/python'
        response=subprocess.run([python,'-I','-m','deployment.control'],input=json.dumps(query),capture_output=True,text=True,timeout=15)
        snap=json.loads(response.stdout)
        assert snap['ok'],snap
        assert snap['data']['budget']['configured'] is (not bool(fault))
        member=next(user for user in snap['data']['users'] if user['id']==self.member)
        assert member['quota_pool']==(None if fault else 'administrator')
        self.assert_preserved()
        return {'status':result['status'],'core_pids_preserved':True,'member_tcp_preserved':True,'result':result}

    def teardown(self):
        # All paths/accounts below are owned exclusively by this dedicated
        # container, which main() refuses to touch when any baseline exists.
        try:
            listed=run('/usr/bin/systemctl','list-units','--all','--output=json','dazzle-*',check=False)
            units=[entry['unit'] for entry in json.loads(listed.stdout or '[]') if entry['unit'].startswith('dazzle-')]
            if units:
                run('/usr/bin/systemctl','stop',*units,check=False)
                run('/usr/bin/systemctl','disable',*units,check=False)
            super().teardown()
        finally:
            for path in ('/etc/tmpfiles.d/dazzle-vps-portal.conf','/run/dazzle-vps-portal'):
                target=Path(path)
                if target.is_dir():shutil.rmtree(target)
                else:target.unlink(missing_ok=True)
            for target in Path('/etc/systemd/system').glob('dazzle-*.service.d'):
                shutil.rmtree(target)
            run('/usr/sbin/userdel','dazzle-web',check=False)
            run('/usr/sbin/groupdel','dazzle-web',check=False)
            run('/usr/bin/systemctl','daemon-reload',check=False)


def main():
    if not (Path('/.dockerenv').exists() and Path('/etc/dazzle-handoff-isolated-container').exists()
            and os.geteuid()==0 and Path('/proc/1/comm').read_text().strip()=='systemd'):
        raise SystemExit('Only the dedicated marked disposable systemd container is permitted')
    if 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text():
        raise SystemExit('Ubuntu24.04 required')
    root=next(line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4]=='/')
    if not any(field.startswith('shared:') for field in root[6:root.index('-')]):
        raise SystemExit('Run mount --make-rshared / inside this disposable container first')
    owned=(*OWNED_PATHS,'/etc/tmpfiles.d/dazzle-vps-portal.conf','/run/dazzle-vps-portal')
    if any(Path(path).exists() or Path(path).is_symlink() for path in owned) or list(Path('/etc/systemd/system').glob('dazzle-*')):
        raise SystemExit('Refusing pre-existing production-like paths')
    bin_info=Path('/usr/local/bin').lstat()
    if not stat.S_ISDIR(bin_info.st_mode) or bin_info.st_uid!=0 or bin_info.st_mode & 0o022:
        raise SystemExit('A trusted root-owned /usr/local/bin is required')
    for name in (*ACCOUNTS,'dazzle-web'):
        try:pwd.getpwnam(name)
        except KeyError:pass
        else:raise SystemExit('Refusing pre-existing account '+name)
    for name in (*GROUPS,'dazzle-web'):
        try:grp.getgrnam(name)
        except KeyError:pass
        else:raise SystemExit('Refusing pre-existing group '+name)
    scenarios=sys.argv[1:] or ['success','fail-takeover','hang-takeover','standby-never-ready','admin-success','admin-budget-rejected']
    results={}
    for scenario in scenarios:
        if scenario not in {'success','fail-takeover','hang-takeover','standby-never-ready','admin-success','admin-budget-rejected'}:
            raise SystemExit('Unknown scenario')
        fixture=PhaseBRehearsal(scenario)
        try:
            fixture.setup()
            results[scenario]=fixture.verify_expansion(*fixture.execute_expansion())
            if scenario.startswith('admin-'):
                results[scenario]['administrator']=fixture.execute_admin()
            print(json.dumps({'scenario':scenario,'result':results[scenario]},sort_keys=True),flush=True)
        except BaseException:
            print(fixture.diagnostics(),file=sys.stderr)
            raise
        finally:
            fixture.teardown()
    print(json.dumps({'phase_b_systemd_rehearsal':'passed','results':results,'production_touched':False},sort_keys=True),flush=True)


if __name__=='__main__':
    main()
