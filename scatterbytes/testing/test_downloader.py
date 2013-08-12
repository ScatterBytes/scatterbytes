import os
import math
import shutil
import unittest
import datetime
import threading
from .import util as testutil
from ..client.downloader import SplitChunk
from ..client.downloader import DownloadLog
from ..client.downloader import ThreadedDownloader
from .. import util
from .. import crypt
from ..chunk import Chunk
from ..errors import DownloadError
from ..client import util as client_util

ENCRYPT_PASS = 'oxwZ9eJKgsg+qtDiHQWB2+XOfYZ8S39J/PjM6hpuhqs'
ENCRYPT_KEY = crypt.AESKey.create_pbkdf2(ENCRYPT_PASS)

TEST_FILES = {
    'test_file_1': dict(path=None, size=8 * 10 ** 6)
}


def setup():
    testutil.create_tmp_directory()
    for item in TEST_FILES.items():
        file_properties = item[1]
        size = file_properties['size']
        path = testutil.create_temp_file(size)
        file_properties['path'] = path
        testutil.create_chunks(path, ENCRYPT_KEY)


def teardown():
    testutil.remove_tmp_directory()


def test_chunk_splitting():
    def map_segments(size, seg_count, check_even=False):
        seg_size = size / seg_count
        if size % seg_count:
            seg_size += 1
        segs = []
        # index starts at 0 for byte references
        for i in xrange(seg_count):
            byte_start = i * seg_size
            byte_end = byte_start + seg_size
            if byte_end > size:
                byte_end = size
            segs.append((byte_start, byte_end))
        if check_even:
            assert [r == segs[0] for r in segs]
        io_map.append([size, seg_count, segs])

    min_segment_size = SplitChunk.min_segment_size
    io_map = []
    # all of these are even numbers
    # min segment - should be just the size of the chunk
    io_map.append((min_segment_size - 1, 4, [(0, min_segment_size - 1)]))
    # 1 MB - 4 parts
    map_segments(10 ** 6, 4, True)
    # 2 MB - 4 parts
    map_segments(2 * 10 ** 6, 4, True)
    # 2 MB - 2 parts
    map_segments(2 * 10 ** 6, 2, True)
    # 2 MB - 20 parts - should only be 15 parts
    map_segments(2 * 10 ** 6, 20, True)
    # io_map.append((2 * 10**6, 20,
    #    [(i*mss, ((i+1)*mss)) for i in xrange(15)])
    #)
    # 2 MB - 1 part
    map_segments(2 * 10 ** 6, 1, True)
    # 1.5 MB - 4 parts
    map_segments(int(1.5 * 10 ** 6), 4, True)
    # uneven segments
    # 1.11 MB - 4 parts
    map_segments(int(1.11 * 10 ** 6), 4)
    # 1.11 MB - 1 part
    map_segments(int(1.11 * 10 ** 6), 1)

    for io_values in io_map:
        (chunk_size, segment_count, expected_result) = io_values
        split_limit = int(
            math.floor(1.0 * chunk_size / SplitChunk.min_segment_size)
        )
        split_limit = max(1, split_limit)
        result = SplitChunk._split(
            chunk_size, split_limit, segment_count
        )
        assert result == expected_result, (result, expected_result)


def test_download_log():
    download_dir = get_chunk_download_dir('some_file_to_download')
    if not os.path.exists(download_dir):
        os.makedirs(download_dir)
    try:
        log = DownloadLog(download_dir)
        # 25 chunk requests with 3 mirrors
        expire_time = datetime.datetime.utcnow() + \
            datetime.timedelta(minutes=60)
        for i in xrange(25):
            chunk_name = testutil.integer_to_chunk_name(i)
            hash_data = os.urandom(4)
            chunk_hash = crypt.calc_hash(hash_data, hash_data)
            chunk_size = 10 ** 6
            chunk_sequence = i
            chunk_info = {
                'chunk_sequence': chunk_sequence,
                'chunk_name': chunk_name,
                'chunk_hash': chunk_hash,
                'chunk_size': chunk_size,
                'download_info': []
            }
            for j in xrange(3):
                download_info = {
                    'uri': '127.0.%i.%i' % (i, j),
                    'expire_time': expire_time,
                    'signature': util.b64encode(os.urandom(32)),
                    'signature_ts': datetime.datetime.utcnow(),
                }
                log.append_download_info(chunk_info, download_info)
        for i in xrange(10):
            log.append_complete(i)
        log.close()
        log_data = DownloadLog.read(log.dir_path)
        chunk_info = log_data['chunk_info']
    finally:
        shutil.rmtree(download_dir)


def get_chunk_dir(file_name=None):
    # this is the source test directory
    if file_name is None:
        file_name = 'test_file_1'
    test_file_path = TEST_FILES[file_name]['path']
    dir_name = os.path.dirname(test_file_path)
    file_name = os.path.basename(test_file_path)
    output_dir = os.path.join(dir_name, '%s_chunks' % file_name)
    return output_dir


def get_chunk_download_dir(file_name, volume_name='v1'):
    download_dir = os.path.join(testutil.TEST_DIR, 'downloads')
    return ThreadedDownloader.get_chunk_download_dir(
        download_dir, volume_name, file_name
    )


class ControlNodeMock(object):

    def __init__(self, files_info):
        self.file_chunks = {}
        self.files_info = files_info
        # use the same salt for everything
        self.salt = os.urandom(4)

    def analyze_chunks(self, file_name):
        if file_name not in self.file_chunks:
            chunks = []
            chunk_dir = get_chunk_dir()
            chunk_names = sorted(os.listdir(chunk_dir))
            for name in chunk_names:
                path = os.path.join(chunk_dir, name)
                chunks.append(Chunk(path))
            self.file_chunks[file_name] = chunks
        return self.file_chunks[file_name]

    def get_file_info(self, volume_name, file_name):
        file_info = self.files_info[volume_name][file_name]
        return file_info

    def request_chunks(self, volume_name, file_name, chunk_offset,
                       chunk_limit, nodes_per_chunk):
        chunks = self.analyze_chunks(file_name)
        chunk_info = []
        for i in xrange(chunk_offset, chunk_limit):
            chunk = chunks[i]
            chunk_record = {
                'chunk_name': '%s-%s' % (file_name, chunk.file_name),
                'chunk_hash': chunk.calc_hash(self.salt),
                'chunk_size': chunk.size,
                'download_info': []
            }
            # download info
            download_info = chunk_record['download_info']
            sig_ts = datetime.datetime.utcnow()
            expire_time = sig_ts + datetime.timedelta(minutes=60)
            for j in xrange(nodes_per_chunk):
                node_download_info = {}
                node_download_info['uri'] = ''
                node_download_info['signature'] = ''
                node_download_info['signature_ts'] = sig_ts
                node_download_info['expire_time'] = expire_time
                download_info.append(node_download_info)
            chunk_info.append(chunk_record)
        assert chunk_info
        return dict(chunk_info=chunk_info)


# need to protect access to files
STORAGE_NODE_LOCK = threading.Lock()


class StorageNodeMock(object):

    requested_chunks = {}

    def __init__(self):
        self.fail_times = 0

    def retrieve_chunk(self, sig, sig_ts, expire_time, chunk_name,
                       byte_start=0, byte_end=0):
        with STORAGE_NODE_LOCK:
            if self.fail_times:
                req_name = '%s-%s-%s' % (chunk_name, byte_start, byte_end)
                if req_name not in self.requested_chunks:
                    self.requested_chunks[req_name] = 0
                self.requested_chunks[req_name] += 1
                if self.fail_times >= self.requested_chunks[req_name]:
                    raise Exception
            # mock storage node uses file_name-chunk_name
            (file_name, chunk_name) = chunk_name.split('-')
            output_dir = get_chunk_dir(file_name)
            chunk_path = os.path.join(output_dir, chunk_name)
            f = open(chunk_path, 'rb')
            # byte range is inclusive
            return util.LimitedFileReader(f, byte_start, byte_end)


def snode_proxy_creator(url):
    return StorageNodeMock()


def create_failing_snode_proxy_creator(fail_times):
    def failing_snode_proxy_creator(url):
        mock = StorageNodeMock()
        mock.fail_times = fail_times
        return mock
    return failing_snode_proxy_creator


class BasicTestCase(unittest.TestCase):

    def setUp(self):
        volume_name = 'v1'
        file_name = 'test_file_1'
        chunk_count = len(os.listdir(get_chunk_dir(file_name)))
        files_info = {
            volume_name: {
                file_name: {
                    'chunk_count': chunk_count,
                    'mirror_count': 3,
                    'flags': client_util.create_flags(
                        compressed=True, encrypted=True
                    )
                }
            }

        }
        download_dir = get_chunk_download_dir(file_name)
        self.download_dir = download_dir
        if not os.path.exists(download_dir):
            os.makedirs(download_dir)
        output_path = os.path.join(testutil.TEST_DIR, file_name)
        control_node_proxy = ControlNodeMock(files_info)
        file_info = control_node_proxy.get_file_info(volume_name, file_name)
        file_info['volume_name'] = volume_name
        file_info['file_name'] = file_name
        self.downloader = ThreadedDownloader(
            file_info, control_node_proxy, snode_proxy_creator, 10,
            ENCRYPT_PASS, output_path, download_dir
        )

    def test_download(self):
        self.downloader.download()

    def test_with_one_snode_failure(self):
        snode_proxy_creator = create_failing_snode_proxy_creator(1)
        self.downloader.snode_proxy_creator = snode_proxy_creator
        self.downloader.download()

    def test_with_two_snode_failures(self):
        snode_proxy_creator = create_failing_snode_proxy_creator(2)
        self.downloader.snode_proxy_creator = snode_proxy_creator
        self.assertRaises(DownloadError, self.downloader.download)

    def tearDown(self):
        StorageNodeMock.requested_chunks = {}
        shutil.rmtree(self.download_dir)


class ResumeTestCase(unittest.TestCase):

    def setUp(self):
        self._create_downloader()
        self.downloader.download()
        # remove a few records from the log
        self.downloader.download_log.fsync()
        log_file_path = self.downloader.download_log.file_path
        self.log_file_path = log_file_path
        lines = open(log_file_path, 'rb').readlines()
        new_lines = lines[:-2]
        open(log_file_path, 'wb').writelines(new_lines)

    def _create_downloader(self):
        volume_name = 'v1'
        file_name = 'test_file_1'
        chunk_count = len(os.listdir(get_chunk_dir(file_name)))
        files_info = {
            volume_name: {
                file_name: {
                    'chunk_count': chunk_count,
                    'mirror_count': 3,
                    'flags': client_util.create_flags(
                        compressed=True, encrypted=True
                    )
                }
            }

        }
        download_dir = get_chunk_download_dir(file_name)
        self.download_dir = download_dir
        if not os.path.exists(download_dir):
            os.makedirs(download_dir)
        output_path = os.path.join(testutil.TEST_DIR, file_name)
        control_node_proxy = ControlNodeMock(files_info)
        file_info = control_node_proxy.get_file_info(volume_name, file_name)
        file_info['volume_name'] = volume_name
        file_info['file_name'] = file_name
        self.downloader = ThreadedDownloader(
            file_info, control_node_proxy, snode_proxy_creator, 10,
            ENCRYPT_PASS, output_path, download_dir
        )

    def test_resume(self):
        self._create_downloader()
        self.downloader.download()

    def tearDown(self):
        StorageNodeMock.requested_chunks = {}
        shutil.rmtree(self.download_dir)
