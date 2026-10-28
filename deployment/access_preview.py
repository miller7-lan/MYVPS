"""Pure preview of the additional administrator budget-guard dependency.

No executor: adding this approval is a separate future production change, and
must preserve the existing Core PID, execution settings and all member services.
"""
import hashlib
import uuid
from .helper import validate_policy


def administrator_preview(policy, original_unit, boot_id):
    policy=validate_policy(policy)
    if str(uuid.UUID(boot_id)) != boot_id:
        raise ValueError('A verified boot identity is required')
    identifier=next(key for key,row in policy['workers'].items() if row['role']=='admin')
    if original_unit.count('[Service]') != 1 or original_unit.count('[Unit]') != 1:
        raise ValueError('One complete administrator unit is required')
    unit, service=original_unit.split('[Service]',1)
    if any(line.strip().startswith(('BindsTo=','Requires=')) for line in unit.splitlines()):
        raise ValueError('Existing administrator dependencies require separate review')
    guard='dazzle-vps-meter-guard@'+identifier+'.service'
    unit += '\nBindsTo='+guard+'\nAfter='+guard+'\n'
    rendered=unit+'[Service]'+service
    return {'operation':'administrator_budget_guard_preview','applied':False,'ready_for_approval':False,
            'server_id':policy['server_id'],'worker_id':identifier,
            'unit_path':'/etc/systemd/system/dazzle-admin@'+identifier+'.service','unit':rendered,
            'service_execution_unchanged':rendered.split('[Service]',1)[1]==service,
            'guard':guard,'administrator_preparation_seconds':60,'sample_freshness_seconds':5,
            'root_marker_path':'/etc/dazzle-vps/admin-budget-guard.json',
            'root_marker':{'approved':True,'server_id':policy['server_id'],'worker_id':identifier,'boot_id':boot_id,
                           'reviewed_unit_sha256':hashlib.sha256(rendered.encode()).hexdigest()},
            'pending_gates':['fresh PID/config/counter baseline and exact human approval',
                'verify guard READY with real Native samples; never restart administrator Core',
                'read back actual BindsTo and unchanged PID/NRestarts',
                'configure the reviewed budget within the bounded preparation window'],
            'failure_rule':'Do not alter member units. If preparation cannot complete, restore the reviewed administrator dependency while its guard is still alive; do not claim zero outage after guard expiry.',
            'database_restore':False,'ssh_modified':False,'firewall_modified':False}
