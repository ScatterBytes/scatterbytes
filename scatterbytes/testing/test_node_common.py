import os
import shutil
import unittest
from . import util as test_util
from . import ssl as test_ssl_
from ..node import download_certificates


def setup():
    test_util.setup_logging()
    test_util.create_tmp_directory()
    test_ssl_.gen_ssl_all()


def setup_ssl_dir():
    ssl_dir_path = os.path.join(test_util.TEST_DIR, 'download_cert_ssl')
    os.mkdir(ssl_dir_path)
    ca_root_cert_src_path = os.path.join(
        test_ssl_.get_ssl_dir(), 'ca_root', 'cert.pem'
    )
    ca_root_cert_tgt_path = os.path.join(ssl_dir_path, 'ca_root_cert.pem')

    shutil.copy(ca_root_cert_src_path, ca_root_cert_tgt_path)
    return ssl_dir_path


class ControlNodeMockup(object):

    def __init__(self):
        self.fail = 0
        self.fail_times = 0

    def get_certificates(self):
        if self.fail_times < self.fail:
            self.fail_times += 1
            raise StandardError('failing for test')
        zip_path = os.path.join(
            test_ssl_.get_ssl_dir(), 'scatterbytes_certs.zip'
        )
        f = open(zip_path, 'rb')
        return f


class DownloadCertNormalTestCase(unittest.TestCase):

    def setUp(self):
        self.ssl_dir = setup_ssl_dir()

    def test_download_certificates(self):
        ssl_dir = self.ssl_dir
        control_node_proxy = ControlNodeMockup()
        download_certificates(control_node_proxy, ssl_dir)

    def tearDown(self):
        shutil.rmtree(self.ssl_dir)


class DownloadCertControlNodeFailureTestCase(unittest.TestCase):

    def setUp(self):
        self.ssl_dir = setup_ssl_dir()

    def test_download_certificates(self):
        ssl_dir = self.ssl_dir
        control_node_proxy = ControlNodeMockup()
        control_node_proxy.fail = 1
        download_certificates(
            control_node_proxy, ssl_dir, retries=1
        )

    def tearDown(self):
        shutil.rmtree(self.ssl_dir)


def teardown():
    test_util.remove_tmp_directory()
