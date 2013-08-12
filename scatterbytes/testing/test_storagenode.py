import os
import gzip
import time
import shutil
import logging
import datetime
import tempfile
import unittest
import threading
from .. import util
from ..crypt import Certificate
from ..storage.node import StorageNode
from ..storage.node import create_storage_node
from ..storage.node import IntegrityChecker
from ..storage.node import TaskScheduler, Task
from ..storage.node import collect_recovery_info
from ..client.chunk import split_file, append_checksum
from . import util as testutil
from . import ssl
from . import node as node_util

TEST_FILE_PATH = None
TEST_CHUNKS = None

logger = logging.getLogger(__name__)

def make_id_generator():
    i = 0
    lock = threading.Lock()
    while 1:
        with lock:
            i += 1
            yield util.base10_to_base32(i).rjust(13, 'A')

chunk_name_generator = make_id_generator()

transfer_name_generator = make_id_generator()

def gen_chunk_name():
    return 'C-%s' % chunk_name_generator.next().rjust(13, 'A')

def gen_transfer_name():
    return 'T-%s' % transfer_name_generator.next().rjust(13, 'A')

def create_salt():
    salt = os.urandom(4)
    b64_salt = util.b64encode(salt)
    return (salt, b64_salt)

class ControlNodeMockup(object):
    
    """

    storage_node
        the calling storage node - assigned after init

    """

    def __init__(self):
        self.transfers = {}
        self._sigkey = ssl.get_sig_key('relay_command_signer')
        cert_path = os.path.join(
            ssl.get_ssl_owner_dir('control_node'), 'cert.pem'
        )
        self._cert = Certificate(cert_path)

    def _sign_args(self, args):
        self._sigkey.sign(args)

    def get_certificates(self):
        ssl_dir = ssl.get_ssl_dir()
        certs_zip_path = os.path.join(ssl_dir, 'scatterbytes_certs.zip')
        return file(certs_zip_path, 'rb')

    def create_certificate(self, node_id, cert_code, csr_pem):
        csr_path = os.path.join(testutil.TEST_DIR, 'tmp_csr.pem')
        open(csr_path, 'wb').write(csr_pem)
        cert_path = ssl.create_cert_from_csr(csr_path)
        return dict(certificate=open(cert_path, 'rb').read())

    def confirm_transfer(self, transfer_name, chunk_name, chunk_hash):
        xfer = self.transfers[transfer_name]
        chunk = xfer['chunk']
        calc_hash = chunk.calc_hash(util.b64decode(chunk.salt))
        assert chunk_hash == calc_hash, '%s, %s' % (chunk_hash, calc_hash)
        node_id = xfer['receiving_node_id']
        self.confirm_transfer_args = [node_id, transfer_name, chunk_hash]
        response = dict(chunk_name=self.transfers[transfer_name]['chunk_name'])
        return response

    def replace_chunks(self, chunk_names):
        self.replaced_chunk_names = chunk_names

    def unregister_storage_node(self):
        pass


def setup():
    # everything else goes there in here
    TEST_DIR = testutil.create_tmp_directory()
    global TEST_FILE_PATH
    TEST_FILE_PATH = testutil.create_temp_file(int(2**22 * 1.5))
    output_dir = os.path.join(TEST_DIR, 'file_chunks')
    os.mkdir(output_dir)
    logger.debug('splitting file %s' % TEST_FILE_PATH)
    chunks = split_file(TEST_FILE_PATH, output_dir, compress=False)
    global TEST_CHUNKS
    TEST_CHUNKS = chunks
    logger.debug('done splitting file')
    # generate ssl keys and certs
    ssl.gen_ssl_all()

def make_expiretime(delta):
    now = datetime.datetime.utcnow()
    then = now + datetime.timedelta(minutes=delta)
    return then

def init_node(storage_node):
    # download certs, generate private key and cert
    assert storage_node.node_id, 'Must set the node id for %s' % storage_node
    storage_node.load_certificates()
    pkey_src_path = ssl.get_key_path(owner_name=storage_node.node_id)
    pkey_tgt_path = storage_node.config.private_key_path
    ##shutil.copy2(pkey_src_path, pkey_tgt_path)
    storage_node._create_private_key()
    storage_node.request_new_certificate()


class BaseMixIn(object):

    def _upload_chunk(self, chunk, transfer_name, chunk_name, hash_salt):
        chunk_name = gen_chunk_name()
        chunk_size = chunk.size
        expire_time = make_expiretime(2)
        transfers = self.control_node_proxy.transfers
        transfers[transfer_name] = {
            'chunk' : chunk,
            'receiving_node_id': self.storage_node.node_id,
            'chunk_name' : chunk_name
        }
        # store the salt
        chunk.salt = hash_salt
        self.transfer = transfers[transfer_name]
        self.transfer_name = transfer_name
        # auth relayed from the server through the client
        cert_info = self.client_cert_info
        # sender serial, receiver serial, .., ..
        sn_args = [1002, self.storage_node.certificate.serial_number,
                   expire_time, transfer_name, chunk_name, hash_salt]
        self.control_node_proxy._sign_args(sn_args)
        sn_args.insert(0, cert_info)
        f = open(chunk.file_path, 'rb')
        sn_args.append(f)
        # remove serial numbers
        sn_args.pop(3)
        sn_args.pop(3)
        response = self.storage_node.store_chunk(*sn_args)
        self.assertEqual(response, 'OK')

    def test_check_hash(self):
        chunk = TEST_CHUNKS[3]
        (salt, b64_salt) = create_salt()
        self._upload_chunk(
            chunk, gen_transfer_name(), gen_chunk_name(), b64_salt
        )
        chunk_name = self.transfer['chunk_name']
        hash = chunk.calc_hash(salt)
        cert_info = self.control_node_proxy._cert.info
        response = self.storage_node.check_hash(
            cert_info, chunk_name, b64_salt
        ) 
        self.assertEqual(response['chunk_hash'], hash)


class InitializationTestCase(unittest.TestCase, BaseMixIn):

    def setUp(self):
        node_id = 'ABCD'
        config = node_util.prepare_node(node_id)
        self.control_node_proxy = ControlNodeMockup()
        self.storage_node = create_storage_node(
            self.control_node_proxy, StorageNode, config=config
        )
        self.control_node_proxy.storage_node = self.storage_node
        init_node(self.storage_node)
        self.client_cert_info = dict(serial_number=1002, CN='XYZ')


    def tearDown(self):
        self.storage_node.shutdown()


class BasicTestCase(unittest.TestCase, BaseMixIn):

    def setUp(self):
        node_id = 'ABCD'
        config = node_util.prepare_node(node_id, initialize=True)
        self.control_node_proxy = ControlNodeMockup()
        self.storage_node = create_storage_node(
            self.control_node_proxy, StorageNode, config=config
        )
        self.control_node_proxy.storage_node = self.storage_node
        self.client_cert_info = dict(serial_number=1002, CN='XYZ')

    def test_store_chunk(self):
        chunk = TEST_CHUNKS[0]
        transfer_name = gen_transfer_name()
        chunk_name = gen_chunk_name()
        (salt, b64_salt) = create_salt()
        self._upload_chunk(chunk, transfer_name, chunk_name, b64_salt)
        # check what was sent to the server
        cn_proxy = self.control_node_proxy
        args = cn_proxy.confirm_transfer_args
        self.assertEqual(args[0], self.storage_node.node_id)
        self.assertEqual(args[1], transfer_name)
        self.assertEqual(args[2], chunk.calc_hash(salt))
        new_path = self.storage_node.config.find_chunk_path(
                                    self.transfer['chunk_name'])
        self.assert_(os.path.exists(new_path))

    def test_retrieve_chunk(self):
        chunk = TEST_CHUNKS[3]
        expire_time = make_expiretime(30)
        (salt, b64_salt) = create_salt()
        self._upload_chunk(
            chunk, gen_transfer_name(), gen_chunk_name(), b64_salt
        )
        chunk_name = self.transfer['chunk_name']
        f = open(chunk.file_path, 'rb')
        f.seek(30)
        byte = f.read(1)
        f.seek(0)
        expire_time = make_expiretime(5)
        cert_info = self.client_cert_info
        # sender serial, receiver serial, .., ..
        auth_args = [1002, self.storage_node.certificate.serial_number,
                     expire_time, chunk_name]
        self.control_node_proxy._sign_args(auth_args)
        args = auth_args
        args.insert(6, 31)
        args.insert(6, 30)
        args.insert(0, cert_info)
        # remove serial
        args.pop(2)
        args.pop(2)
        (f, file_size) = self.storage_node.retrieve_chunk(*args) 
        self.assertEqual(f.read(), byte)
     
    def test_delete_chunk(self):
        chunk = TEST_CHUNKS[3]
        (salt, b64_salt) = create_salt()
        self._upload_chunk(
            chunk, gen_transfer_name(), gen_chunk_name(), b64_salt
        )

        chunk_name = self.transfer['chunk_name']
        chunk_path = self.storage_node.config.find_chunk_path(chunk_name)
        self.assert_(os.path.exists(chunk_path))
        cert_info = self.control_node_proxy._cert.info
        response = self.storage_node.delete_chunk(cert_info, chunk_name)
        self.assertEqual(response, 'OK')
        self.assert_(not os.path.exists(chunk_path))

    def tearDown(self):
        self.storage_node.shutdown()
        del self.storage_node

class BaseIntegrityCheckerTestCase(unittest.TestCase):

    def setUp(self):
        # create a bunch of normal chunks
        storage_directory = tempfile.mkdtemp(prefix='rcs_recovery',
                                             dir=testutil.TEST_DIR)
        self.storage_directory = storage_directory
        self.control_node_proxy = ControlNodeMockup()
        self.control_node_proxy.authenticate = False
        file_count = 10**4
        self.chunk_paths = []
        for i in xrange(file_count):
            data = os.urandom(10)
            name = gen_chunk_name()
            prefix = name[:2]
            chunk_dir_path = os.path.join(storage_directory, prefix)
            if not os.path.exists(chunk_dir_path):
                os.makedirs(chunk_dir_path)
            chunk_path = os.path.join(chunk_dir_path, name)
            assert not os.path.exists(chunk_path)
            open(chunk_path, 'wb').write(data)
            append_checksum(chunk_path)
            self.chunk_paths.append(chunk_path)

    def tearDown(self):
        shutil.rmtree(self.storage_directory)

class NormalIntegrityCheckerTestCase(BaseIntegrityCheckerTestCase,
                                     unittest.TestCase):
    def setUp(self):
        BaseIntegrityCheckerTestCase.setUp(self)

    def test_integrity_check(self):
        checker = IntegrityChecker(self.storage_directory,
                                   self.control_node_proxy)
        checker.start()
        checker.join()

    def tearDown(self):
        BaseIntegrityCheckerTestCase.tearDown(self)

class ReplaceIntegrityCheckerTestCase(BaseIntegrityCheckerTestCase,
                                      unittest.TestCase):
    def setUp(self):
        BaseIntegrityCheckerTestCase.setUp(self)
        # corrupt a few files
        for chunk_path in self.chunk_paths[:7]:
            print chunk_path
            data = open(chunk_path, 'rb').read()
            data = data[5:]
            open(chunk_path, 'wb').write(data)

    def test_integrity_check(self):
        checker = IntegrityChecker(self.storage_directory,
                                   self.control_node_proxy)
        checker.start()
        checker.join()
        chunk_names = [os.path.basename(c) for c in self.chunk_paths[:7]]
        chunk_names.sort()
        central_chunk_names = self.control_node_proxy.replaced_chunk_names
        central_chunk_names.sort()
        self.assertEqual(chunk_names, central_chunk_names)

    def tearDown(self):
        BaseIntegrityCheckerTestCase.tearDown(self)

class FailIntegrityCheckerTestCase(BaseIntegrityCheckerTestCase,
                                      unittest.TestCase):
    def setUp(self):
        BaseIntegrityCheckerTestCase.setUp(self)
        # corrupt a few files
        for chunk_path in self.chunk_paths[:11]:
            print chunk_path
            data = open(chunk_path, 'rb').read()
            data = data[5:]
            open(chunk_path, 'wb').write(data)

    def test_integrity_check(self):
        checker = IntegrityChecker(self.storage_directory,
                                   self.control_node_proxy)
        checker.start()
        checker.join()

    def tearDown(self):
        BaseIntegrityCheckerTestCase.tearDown(self)

def test_collect_recovery_info():
    # create a bunch of files with some random information in them.
    storage_dir_path = tempfile.mkdtemp(prefix='rcs_recovery',
                                        dir=testutil.TEST_DIR)
    file_count = 10**4
    try:
        for i in xrange(file_count):
            data = os.urandom(10)
            name = gen_chunk_name()
            prefix = name[:2]
            chunk_dir_path = os.path.join(storage_dir_path, prefix)
            if not os.path.exists(chunk_dir_path):
                os.makedirs(chunk_dir_path)
            chunk_path = os.path.join(chunk_dir_path, name)
            assert not os.path.exists(chunk_path)
            open(chunk_path, 'wb').write(data)
        (handle, output_path) = tempfile.mkstemp(prefix='rcs_recovery',
                                                suffix='.gz')
        try:
            collect_recovery_info(storage_dir_path, output_path)
            # should have file_count lines
            line_count = 0
            for line in gzip.open(output_path):
                line_count += 1
            assert line_count == file_count
        finally:
            os.unlink(output_path)
    finally:
        shutil.rmtree(storage_dir_path)

def test_task_scheduler():
    shutdown_event = threading.Event()

    class Task1(Task):

        def __init__(self):
            Task.__init__(self)
            self.var1 = 0

        def run(self):
            self.var1 += 1
            if self.var1 > 2:
                # should be caught and logged
                raise StandardError('something bad happened')

    class Task2(Task):

        def __init__(self):
            Task.__init__(self)
            self.var1 = 0

        def run(self):
            self.var1 += 2

    task1 = Task1()
    task2 = Task2()

    scheduler = TaskScheduler(
            tasks=[task1, task2], shutdown_event=shutdown_event
    )
    scheduler.start()
    time.sleep(.5)
    shutdown_event.set()
    scheduler.join()
    assert task1.var1 > 0
    assert task2.var1 > 0

def teardown():
    testutil.remove_tmp_directory()
