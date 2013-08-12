import os
import time
import shutil
import random
import hashlib
import logging
import unittest
import datetime
import tempfile
import threading
from .. import util
from ..client import chunk as chunklib
from ..client.chunk import split_file
from ..client.chunk import calc_chunk_sizes
from ..client.node import ClientNode
from ..client.node import UploadLog
from ..client.node import ClientNodeConfig
from . import util as testutil

logger = logging.getLogger(__name__)

TEST_FILE_PATH = None

def setup():
    testutil.create_tmp_directory()
    global TEST_FILE_PATH
    TEST_FILE_PATH = testutil.create_temp_file(int(2**21 * 5.1))

def get_config_path(node_id):
    config_path = os.path.join(
        testutil.TEST_DIR, 'client_nodes', node_id,
        ClientNodeConfig.config_name
    )
    if not os.path.exists(config_path):
        os.makedirs(config_path)
    return config_path



class BasicTestCase(unittest.TestCase):
    
    def setUp(self):
        self.node_id = 'XYZ'
        control_node_proxy = ControlNodeMockup()
        config_path = get_config_path(self.node_id)
        config = ClientNodeConfig(config_path=config_path)
        self.client_node = ClientNode(control_node_proxy, StorageNodeMockup,
                                      config=config)
        self.control_node = control_node_proxy

    def test_upload_chunks(self):
        file_path = TEST_FILE_PATH
        node = self.client_node
        file_chunks_path = node.prepare_file(
            file_path, encrypt=False, compress=False
        )
        volume_name = 'volume1'
        thread_count = 3
        filename = 'testfilename'
        metadata = {}
        node.upload_file_chunks(
            file_chunks_path, volume_name, thread_count, filename,
            metadata
        )

    def test_prepare_file(self):
        file_path = TEST_FILE_PATH
        chunk_output_dir = self.client_node.prepare_file(
            file_path, encrypt=False, compress=False
        )
        # The low level stuff is tested in chunk unit tests. Just make sure
        # this doesn't cause errors and creates files.
        file_chunk_names = os.listdir(chunk_output_dir)
        assert file_chunk_names and [c.startswith('chunk') for c in 
                                     file_chunk_names]

    def test_prepare_file_encrypt_and_compress(self):
        file_path = TEST_FILE_PATH
        chunk_output_dir = self.client_node.prepare_file(file_path)
        file_chunk_names = os.listdir(chunk_output_dir)
        assert file_chunk_names and [c.startswith('chunk') for c in 
                                     file_chunk_names]
      

    ##def testDownloadFile(self):
    ##    file_path = TEST_FILE_PATH
    ##    volume_name = 'default'
    ##    self.client_node.upload_file(file_path, volume_name, compress=False,
    ##                                 encrypt=False)
    ##    output_path = self.client_node.config.get('working_directory')
    ##    file_output_path = os.path.join(output_path, 'testfile')
    ##    self.client_node.download_file(file_path, file_output_path)

    def tearDown(self):
        pass


class ControlNodeMockup(object):
    
    authenticate = False
    
    def __init__(self):
        self.chunk_id = 0
        self.chunk_id_lock = threading.Lock()
        self.transfer_id = 0
        self.transfer_id_lock = threading.Lock()
        self.mirror_lock = threading.Lock()
        self.request_storage_responses = []
        self.requested_chunk_info = []
        self.chunk_info = {}
        self._sequence_number = 1

    def gen_chunk_name(self):
        with self.chunk_id_lock:
            self.chunk_id += 1
            return util.base10_to_base32(self.chunk_id).rjust(12, 'A')

    def gen_transfer_name(self):
        with self.transfer_id_lock:
            self.transfer_id += 1
            return 'T-' + \
                util.base10_to_base32(self.transfer_id).rjust(12, 'A')

    def create_file(self, volume_name, filename, size, flags, metadata):
        return dict(status='OK')

    def _gen_relay_info(self, chunk_sequence_number):
        signature = 'sig does not matter here'
        signature_ts = datetime.datetime.utcnow()
        sender_cert_id = 1 # doesn't matter here
        receiver_cert_id = 2 # doesn't matter here
        transfer_name = self.gen_transfer_name()
        chunk_name = self.gen_chunk_name()
        expire_time = make_expire_time(30)

        info = {
            'uri' : "https://127.0.0.1:12345",
            'sequence_number' : chunk_sequence_number,
            'signature': signature,
            'signature_ts': signature_ts,
            'expire_time': expire_time,
            'transfer_name': transfer_name,
            'chunk_name': chunk_name,
            'chunk_hash_salt' : util.b64encode(os.urandom(4))
        }
        return info

    def request_file_storage(self, volume_name, file_name, chunk_info):
        # There is no networking involved in these tests.  The response just
        # needs to work with the StorageNodeMockup class.

        transfer_info = []
        for chunk_i in chunk_info:
            transfer_info.append(self._gen_relay_info(self._sequence_number))
            self._sequence_number += 1
        response = dict(transfer_info=transfer_info)
        return response

    def check_mirror_status(self, volume_name, file_name):
        # the first time, respond with 0
        full_file_name = '%s_%s' % (volume_name, file_name)
        with self.mirror_lock:
            if not hasattr(self, '_file_mirror_status'):
                self._file_mirror_status = {}
            if full_file_name in self._file_mirror_status:
                min_count = 1
            else:
                self._file_mirror_status[full_file_name] = 0
                min_count = 0
            return dict(min_count=min_count)

    def request_chunks(self, file_id, chunk_offset, chunk_limit, 
                       nodes_per_chunk):
        expire_time = make_expire_time(30)
        snode_info = []
        assert len(chunk_ids) == len(self.chunk_info)
        for chunk_id in chunk_ids:
            chunk_info = self.chunk_info[chunk_id]
            snode_args = ['retrieve_chunk', chunk_id, expire_time]
            SNODE_AUTH.sign(snode_args)
            uri = "https://%s:%s" (chunk_info['snode_info']['ip_address'],
                                   chunk_info['snode_info']['port'])
            snode_info.append({
                'uri' : uri,
                'chunk_name' : chunk_name,
                'storage_node_args': snode_args,
            })
        response = {}
        response.update({
            'chunk_info': snode_info,
        })
        print response
        return response

    def report_failed_transfer(self, transfer_name):
        return {'transfer_info' : {}}

class StorageNodeMockup(object):

    _chunk_dir = None
    
    def __init__(self, url):
        self.url = url
        self.uploaded_chunk_data = []
        self.chunks = []

    def store_chunk(self, auth, auth_ts, expire_time, transfer_id,
                                chunk_name, chunk_hash_salt, chunk_file):
        assert hasattr(chunk_file, 'read')
        
    def retrieve_chunk(self, auth, auth_ts, method_name, chunk_id,
                       expire_time):
        chunk_path = os.path.join(self._chunk_dir, str(chunk_id).zfill(8))
        return open(chunk_path, 'rb')


def test_upload_log():
    # need to have a few threads writing

    # these are to be the chunk_id values assigned by the control node
    bad_chunks = [6, 13, 66]

    upload_log = UploadLog(testutil.TEST_DIR)

    class LogWriter(threading.Thread):
        def __init__(self, chunks):
            threading.Thread.__init__(self)
            self.chunks = chunks

        def run(self):
            for chunk_sequence_number in self.chunks:
                # wait some period of time
                time.sleep(random.randint(1, 10) / 50.0)
                chunk_file_name = 'chunk_%s' % str(
                                            chunk_sequence_number).zfill(10)
                upload_log.append_assignment(chunk_file_name)
                if chunk_sequence_number not in bad_chunks:
                    upload_log.append_complete(chunk_file_name)
            upload_log.fsync()

    writers = []
    chunks = []
    for i in xrange(100):
        chunks.append(i)
        if i and not i % 10:
            writers.append(LogWriter(chunks))
            chunks = []
    for writer in writers:
        writer.start()
    for writer in writers:
        writer.join()
    upload_log.close()

    incomplete_chunk_names = UploadLog.read_incomplete(testutil.TEST_DIR)
    incomplete_chunk_sequence_numbers = \
        [int(n.split('_')[-1]) for n in incomplete_chunk_names]
    for chunk_sequence_number in bad_chunks:
        assert chunk_sequence_number in incomplete_chunk_sequence_numbers

def make_expire_time(delta):
    expire_time = datetime.datetime.utcnow() + \
            datetime.timedelta(minutes=delta)
    return expire_time

def teardown():
    testutil.remove_tmp_directory()
