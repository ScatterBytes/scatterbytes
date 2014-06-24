import os
import math
import shutil
import random
import hashlib
import logging
import tempfile
import unittest
from . import util as testutil
from .. import util
from ..crypt import AESKey
from ..client.chunk import split_file
from ..client.chunk import combine_chunks
from ..client.chunk import calc_chunk_sizes
from ..client.chunk import CHUNK_SIZE_MIN, CHUNK_SIZE_MAX

TEST_FILE_PATH = None
DATA_DIR = None
ENC_PASSPHRASE = util.b64encode(os.urandom(16))

logger = logging.getLogger(__name__)

def setup():
    # need some data to work with
    global DATA_DIR
    DATA_DIR = testutil.create_tmp_directory()
    logger.debug('creating test file ...')
    byte_count = int(7.31 * 10**6)
    global TEST_FILE_PATH
    TEST_FILE_PATH = testutil.create_temp_file(byte_count)
    logger.debug('done with test file')


class BaseTestCase(object):

    compress = False
    encrypt_key = None
    expected_chunk_sizes = []

    def setUp(self):
        self.file_path = TEST_FILE_PATH
        self.file_size = os.stat(self.file_path).st_size
        self.tmp_dir = tempfile.mkdtemp(prefix='rcs_')
        self.output_dir = os.path.join(self.tmp_dir, 'chunks')
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def test_split_file(self):
        chunks = split_file(self.file_path, self.output_dir,
                        compress=self.compress, encrypt_key=self.encrypt_key)
        raw_data = chunks[0].read(raw=True)
        if self.expected_chunk_sizes:
            for (i, chunk) in enumerate(chunks):
                self.assertEqual(chunk.size - 4, self.expected_chunk_sizes[i])

    def test_combine_chunks(self):
        chunks = split_file(self.file_path, self.output_dir,
                        compress=self.compress, encrypt_key=self.encrypt_key)
        output_path = os.path.join(self.tmp_dir, 'combined_file')
        combine_chunks(chunks, output_path, decompress=self.compress,
                                encrypt_key=self.encrypt_key)
        self.assertEqual(
            hashlib.sha1(open(self.file_path, 'rb').read()).digest(),
            hashlib.sha1(open(output_path, 'rb').read()).digest())

    def tearDown(self):
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)


class ExactChunkSizeTestCase(unittest.TestCase, BaseTestCase):

    """testing a different file size"""

    compress = True
    encrypt_key = AESKey.create_pbkdf2(ENC_PASSPHRASE)

    def setUp(self):
        BaseTestCase.setUp(self)
        self.file_path = testutil.create_temp_file(2**21)

    def tearDown(self):
        BaseTestCase.tearDown(self)


class BasicTestCase(unittest.TestCase, BaseTestCase):

    def setUp(self):
        BaseTestCase.setUp(self)
        self.expected_chunk_sizes = calc_chunk_sizes(self.file_size)

    def tearDown(self):
        BaseTestCase.tearDown(self)


class EncryptionTestCase(unittest.TestCase, BaseTestCase):

    compress = True
    encrypt_key = AESKey.create_pbkdf2(ENC_PASSPHRASE)

    def setUp(self):
        BaseTestCase.setUp(self)

    def tearDown(self):
        BaseTestCase.tearDown(self)


class SmallDataTestCase(unittest.TestCase, BaseTestCase):

    expected_header_size = 1000

    def setUp(self):
        BaseTestCase.setUp(self)
        (handle, self.file_path) = tempfile.mkstemp(prefix='rcs_')
        # need some header values
        open(self.file_path, 'wb').write(os.urandom(8))

    def tearDown(self):
        os.unlink(self.file_path)
        BaseTestCase.tearDown(self)


class JustCompressionTestCase(unittest.TestCase, BaseTestCase):

    compress = True

    def setUp(self):
        BaseTestCase.setUp(self)

    def tearDown(self):
        BaseTestCase.tearDown(self)


##class SimpleParityTestCase(unittest.TestCase):
##
##    def setUp(self):
##        # need a big file
##        self.tmp_file_path = testutil.create_temp_file(
##                                        int(10**6 * 42.14))
##        self.output_dir = tempfile.mkdtemp(dir=DATA_DIR)
##        logger.debug('output_dir is %s' % self.output_dir)
##        self.restore_path = os.path.join(self.output_dir, 'restored_file')
##
##    def testCreateParity(self):
##        chunks = chunklib.split_file(self.tmp_file_path, self.output_dir,
##                                     encrypt=False, compress=False)
##
##    def testReconstruct(self):
##        chunks = chunklib.split_file(self.tmp_file_path, self.output_dir,
##                                     encrypt=False, compress=False)
##        # should be able to wipe out the 2 biggest chunks and recover
##        os.unlink(chunks[0].file_path)
##        os.unlink(chunks[1].file_path)
##        chunklib.combine(chunks, self.restore_path, decrypt=False,
##                         decompress=False)
##        self.assertEqual(
##            hashlib.sha256(open(self.tmp_file_path, 'rb').read()).digest(),
##            hashlib.sha256(open(self.restore_path, 'rb').read()).digest())
##
##    def tearDown(self):
##        logger.debug('removing %s' % self.output_dir)
##        shutil.rmtree(self.output_dir)
##        if not os.environ.get('RCS_KEEP_TMP'):
##            os.unlink(self.tmp_file_path)

def test_calc_chunk_sizes():

    def check_sizes():
        if data_size < min_size:
            assert len(chunk_sizes) == 1 and \
                            chunk_sizes[0] == min_size, chunk_sizes
        else:
            chunk_sum = sum(chunk_sizes)
            assert chunk_sum == data_size, '%s, %s' % (data_size, chunk_sum)
            assert filter(lambda x: min_size < x < max_size,
                          chunk_sizes), chunk_sizes

    min_size = 2**20
    max_size = min_size * 2
    tgt_size = int(2**20 * 1.5)
    (range_start, range_end) = (1, 2**20 * 5)
    # first for some small sizes
    for i in xrange(10000):
        data_size = random.randint(range_start, range_end)
        chunk_sizes = calc_chunk_sizes(data_size, min_size, tgt_size,
                                       max_size)
        check_sizes()
    # now for some larger values
    (range_start, range_end) = (2**20 * 5, 2**20 * 10000)
    for i in xrange(1000):
        data_size = random.randint(range_start, range_end)
        chunk_sizes = calc_chunk_sizes(data_size, min_size, tgt_size,
                                       max_size)
        check_sizes()

def teardown():
    testutil.remove_tmp_directory()
