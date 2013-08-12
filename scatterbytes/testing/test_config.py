import os
import unittest
from .. import util
from ..client.node import ClientNodeConfig
from . import util as testutil

class StandardClientTestCase(unittest.TestCase):

    def setUp(self):
        testutil.create_tmp_directory()
        config_path = os.path.join(
            testutil.TEST_DIR, 'client_nodes', 'AAA',
            ClientNodeConfig.config_name
        )
        self.config = ClientNodeConfig(config_path=config_path)

    def test_defaults(self):
        config = self.config
        self.assertEqual(config.get('encrypt', section='data_prep'), True)
        newkey = util.b64encode(os.urandom(32))
        config.encrypt_key = newkey
        self.assertEqual(newkey, config.encrypt_key)
        config.set('encrypt', False, section='data_prep')
        self.assertEqual(config.get('encrypt', section='data_prep'), False)
        self.assertEqual(config.get('compress', section='data_prep'), True)
        self.assertEqual(
            config.get('download_thread_count', section='transfer'), 10
        )
        self.assertEqual(
            config.get('upload_thread_count', section='transfer'), 3
        )

    def tearDown(self):
        testutil.remove_tmp_directory()
