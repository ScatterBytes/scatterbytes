import os
import struct
import logging
from .crypt import calc_file_hash
from .crypt import calc_file_crc32
from .errors import ChecksumError
from .errors import SecureHashError
from .errors import ChunkNotFoundError
from .errors import ChunkChecksumError

logger = logging.getLogger(__name__)

CHUNK_SIZE_MIN = 10 ** 6
CHUNK_SIZE_MAX = CHUNK_SIZE_MIN * 2


def read_crc32_checksum(f):
    """Read the crc32 checksum appended to the data.

    Returns the crc32 checksum as an integer.

    """

    is_file = isinstance(f, file)
    if is_file:
        fl = f
    else:
        fl = open(f, 'rb')
    fl.seek(-4, 2)
    cksum = struct.unpack('<I', fl.read(4))[0]
    if not is_file:
        fl.close()
    return cksum


def checksum_chunk(file_path):
    """checksum file using the stored crc32 value

    Last 4 bytes is a crc32 checksum.

    raises ChunkChecksumError on failure

    """

    cksum = read_crc32_checksum(file_path)
    cksum_calc = calc_file_crc32(file_path, contains_checksum=True)
    if cksum != cksum_calc:
        raise ChunkChecksumError('checksum failed')


class Chunk(object):
    """chunk of a file

    Data always has crc32 checksum appended.

    file_path
        full filesystem path to the chunk

    file_name
        local name for the chunk

    size
        size of the chunk on the filesystem

    """

    def __init__(self, file_path):
        if not os.path.exists(file_path):
            raise ChunkNotFoundError
        self.file_path = file_path

    @property
    def file_name(self):
        return os.path.basename(self.file_path)

    def verify_checksum(self):
        """perform a crc32 checksum"""
        logger.debug('verifying crc32 checksum')
        try:
            checksum_chunk(self.file_path)
        except ChecksumError as e:
            raise ChunkChecksumError(*e.args)

    def verify_hash(self, hash):
        logger.debug('checking hash for %s' % self.file_path)
        logger.debug('expected %s' % hash)
        hash_calc = self.calc_hash()
        logger.debug('got      %s' % hash_calc)
        if hash_calc != hash:
            raise SecureHashError

    def calc_hash(self, salt=None, return_type='base64'):
        """calculate the hash for the chunk

        """
        # if salt length is supplied, the salt should be read from the chunk
        if salt:
            # salt should be 4 bytes
            assert len(salt) == 4
        hash = calc_file_hash(
            self.file_path, salt=salt, return_type=return_type
        )
        logger.debug('hash for %s is %s' % (self.file_path, hash))
        return hash

    @property
    def crc32_checksum(self):
        # returns crc32 as integer
        return read_crc32_checksum(self.file_path)

    @property
    def size(self):
        """size including checksum if present"""
        return int(os.stat(self.file_path).st_size)

    @property
    def chunk_size(self):
        """"size of the chunk, which must be at least CHUNK_SIZE_MIN"""
        return max(self.size, CHUNK_SIZE_MIN)

    def read(self, raw=False, byte_range=None):
        """read data excluding the checksum"""
        f = open(self.file_path, 'rb')
        try:
            if raw:
                return f.read()
            else:
                total_bytes = self.size
                bytes_to_read = total_bytes
                if byte_range:
                    if byte_range[1] <= byte_range[0]:
                        raise ValueError('invalid byte range')
                    f.seek(byte_range[0])
                    return f.read(byte_range[1] - byte_range[0])
                # skip the checksum
                return f.read(bytes_to_read - 4)
        finally:
            f.close()
