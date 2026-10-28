from pathlib import Path
import unittest
import uuid
from deployment.access_preview import administrator_preview
from deployment.helper import CORE_SHA256


class AccessPreviewTests(unittest.TestCase):
    def test_preview_keeps_execution_and_demands_real_adoption_without_applying(self):
        identifier=str(uuid.uuid4())
        policy={'version':1,'server_id':str(uuid.uuid4()),'server_endpoint':'8.8.8.8','agent_uid':995,'core_sha256':CORE_SHA256,
                'workers':{identifier:{'role':'admin','public_port':24430,'api_port':34430}}}
        source=(Path(__file__).resolve().parents[1]/'systemd/dazzle-admin@.service').read_text()
        preview=administrator_preview(policy,source,str(uuid.uuid4()))
        self.assertFalse(preview['applied']);self.assertFalse(preview['ready_for_approval'])
        self.assertTrue(preview['service_execution_unchanged'])
        self.assertEqual(preview['unit'].split('[Service]',1)[1],source.split('[Service]',1)[1])
        self.assertIn('BindsTo='+preview['guard'],preview['unit'])
        with self.assertRaises(ValueError):administrator_preview(policy,source.replace('[Unit]','[Unit]\nBindsTo=other.service'),str(uuid.uuid4()))
