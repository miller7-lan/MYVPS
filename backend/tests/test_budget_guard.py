"""Limited administrators are proxy users; SSH is outside this guard."""
import copy
import unittest
from dazzle.meter_guard import evaluate, GuardError
import test_meter_guard as fixtures
from dazzle.store import utcnow
from dazzle.metering import MeterSample
from dazzle.store import timestamp


class LimitedAdministratorGuardTests(unittest.TestCase):
    def test_only_explicitly_limited_administrator_can_use_the_guard(self):
        now=utcnow()
        view = fixtures.view_fixture(now)
        sample=MeterSample(str(fixtures.EPOCH),fixtures.UPLOAD,fixtures.DOWNLOAD,timestamp(now))
        view=copy.deepcopy(view)
        view['worker']['role']='admin'
        view['user']['role']='admin'
        view['user']['unlimited']=1
        actual={'pid':view['worker']['process_id'],'identity':'fixture-process'}
        with self.assertRaises(GuardError):evaluate(view,actual,sample,now)
        view['user']['unlimited']=0
        self.assertEqual(evaluate(view,actual,sample,now)['phase'],'running')
        view['user']['used_upload']=view['user']['quota_bytes']
        with self.assertRaises(GuardError):evaluate(view,actual,sample,now)
