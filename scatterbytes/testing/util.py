import os
from cStringIO import StringIO

import httplib
import logging
import shutil
import socket
import struct
import tempfile
import urllib

from .. import crypt
from ..client.chunk import split_file
from ..util import base10_to_base32


logger = logging.getLogger(__name__)

FAKE_FILE_HASH = crypt.calc_hash('hello world', 'salt')

TEST_DIR = None

# Data that is expensive to compute, like RSA keys, can be cached between test
# runs by setting the SB_CACHE_DIR environment variable.
CACHE_DIR = None
if 'SB_CACHE_DIR' in os.environ:
    CACHE_DIR = os.path.abspath(os.environ['SB_CACHE_DIR'])
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)


def create_tmp_directory():
    global TEST_DIR
    if TEST_DIR is None:
        TEST_DIR = tempfile.mkdtemp(prefix='sb_tests_')
    # in case it was deleted
    if not os.path.exists(TEST_DIR):
        os.makedirs(TEST_DIR)
    return TEST_DIR


def remove_tmp_directory():
    global TEST_DIR
    if TEST_DIR is not None and os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)


def create_temp_file(byte_count):
    if CACHE_DIR:
        test_files_path = os.path.join(CACHE_DIR, 'test_files')
    else:
        create_tmp_directory()
        test_files_path = os.path.join(TEST_DIR, 'test_files')
    if not os.path.exists(test_files_path):
        os.makedirs(test_files_path)
    # try to find one that exists for this size
    for listing in os.listdir(test_files_path):
        path = os.path.join(test_files_path, listing)
        if listing.startswith('sb_') and os.path.isfile(path) and \
                os.stat(path).st_size == byte_count:
            return path
    (handle, path) = tempfile.mkstemp(prefix='sb_', dir=test_files_path)
    logger.debug('creating test file %s bytes' % byte_count)
    open(path, 'wb').write(os.urandom(byte_count))
    logger.debug('finished creating test file')
    return path


def create_chunks(file_path, key):
    file_name = os.path.basename(file_path)
    dir_name = os.path.dirname(file_path)
    output_dir = os.path.join(dir_name, '%s_chunks' % file_name)
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    if not os.listdir(output_dir):
        split_file(file_path, output_dir, True, key)


def ip_to_integer(ip):
    return struct.unpack('!L', socket.inet_aton(ip))[0]


def integer_to_ip(n):
    return socket.inet_ntoa(struct.pack('!L', n))


def integer_to_chunk_name(i):
    return 'C-%s' % base10_to_base32(i).rjust(13, 'A')


def setup_logging():
    if TEST_DIR:
        logging.basicConfig(
            level=logging.INFO, file=os.path.join(TEST_DIR, 'sbtest.log')
        )


class FakeSock(object):
    """intercepts httplib.HTTPConnection.sock"""

    def __init__(self):
        self._stringio = StringIO()

    def __getattr__(self, name):
        return getattr(self._stringio, name)

    def sendall(self, buffer):
        self._stringio.write(buffer)


def make_http_message(
    host='127.0.0.1', port=80, method='GET', url='/index.html',
    params=None, close_connection=True, user_agent='SB Test Agent',
        accept="text/plain", extra_headers=None, body=None):
    """construct an http message

    if params are given, will override body

    """

    if params or body:
        method = 'POST'
    if params is not None:
        body = urllib.urlencode(params)
    headers = {
        'Accept': accept,
        'User-Agent': user_agent,
    }
    if close_connection:
        headers['Connection'] = 'close'
    if extra_headers:
        headers.update(extra_headers)
    con = httplib.HTTPConnection(host, port)
    con.sock = FakeSock()
    con.request(method, url, body, headers=headers)
    return con.sock.getvalue()
