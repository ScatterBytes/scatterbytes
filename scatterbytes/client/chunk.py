"""handles splitting and recombining files

"""

import os
import zlib
import math
import struct
import logging
import subprocess
# see if encryption is available
try:
    from M2Crypto.EVP import Cipher
except ImportError:
    Cipher = None
# check for multiprocessing - platforms without shared semaphore will raise an
# error
try:
    import multiprocessing
except:
    multiprocessing = None
from ..chunk import Chunk
from ..chunk import CHUNK_SIZE_MIN
from ..chunk import CHUNK_SIZE_MAX
from ..crypt import calc_file_crc32
from ..crypt import AESKey


# Size of the data chunks to be uploaded.
CHUNK_SIZE_TGT = int(CHUNK_SIZE_MIN * 1.5)

CIPHER_ENCODE = 0
CIPHER_DECODE = 1
CIPHER_MODE = 'aes_128_cfb'
# CFB mode doesn't require padding and shouldn't have leftover data so a call
# to final should not be needed.  Assertions are in place to check.

logger = logging.getLogger(__name__)


class ClientChunk(Chunk):

    def __init__(self, file_path):
        Chunk.__init__(self, file_path)
        self.parity = False

    @property
    def sequence_number(self):
        return int(self.file_name.split('_')[-1])

    @classmethod
    def create(cls, raw_data, chunk_dir, prefix='chunk'):
        """create new ClientChunk instance

        chunk_dir
            directory containing this chunk

        """
        other_names = [f for f in os.listdir(chunk_dir) if \
                       f.startswith(prefix)]
        other_names.sort()
        last_digit = 0
        if other_names:
            last_digit = int(other_names[-1].split('_')[-1])
        filename = '%s_%s' % (prefix, str(last_digit + 1).zfill(9))
        logger.debug('creating chunk %s' % filename)
        file_path = os.path.join(chunk_dir, filename)
        f = open(file_path, 'wb')
        f.write(raw_data)
        f.close()
        append_checksum(file_path)
        return ClientChunk(file_path)

def read_chunk_dir(chunk_dir, prefix='chunk'):
    """generate a list of ClientChunks for chunk_dir"""
    chunks = []
    filenames = [f for f in os.listdir(chunk_dir) if f.startswith(prefix)]
    filenames.sort()
    for filename in filenames:
        file_path = os.path.join(chunk_dir, filename)
        chunks.append(ClientChunk(file_path))
    return chunks

def split_file(file_path, chunk_output_dir, compress=True, encrypt_key=None):
        """split the file into chunks

        returns a list of ClientChunk objects

        compress
            compress with gzip

        encrypt_key
            128 bit key used for AES encryption

        128 bit key recommended by Schneier
        https://www.schneier.com/blog/archives/2009/07/another_new_aes.html

        """

        file_size = os.stat(file_path).st_size
        logger.debug('original file size is %s' % file_size)
        chunk_sizes = []
        data_stream = ''
        if encrypt_key:
            esalt = encrypt_key.binary_salt
            if esalt is None:
                esalt = ''
            assert isinstance(encrypt_key, AESKey)
            # account for iv
            # size should be same as key
            iv = os.urandom(16)
            assert len(iv) == len(encrypt_key.binary_key)
            encryptor = Cipher(
                CIPHER_MODE, encrypt_key.binary_key, iv, CIPHER_ENCODE
            )
            data_stream = data_stream + esalt + iv
        if not compress:
            chunk_sizes = calc_chunk_sizes(file_size + len(data_stream))
        logger.debug('splitting %s into %s' % (file_path, chunk_output_dir))
        logger.debug('compress: %s' % compress)
        if encrypt_key:
            logger.debug('encrypt: True')
        f = open(file_path, 'rb')
        chunks = []
        chunk_prefix = 'chunk'
        if compress:
            compressor = zlib.compressobj(9)
            chunk_prefix = 'tmp_chunk'
        # figure out the size of the first chunk
        if chunk_sizes:
            chunk_size = chunk_sizes.pop(0)
        else:
            chunk_size = CHUNK_SIZE_MAX

        def chunk_stream(data_stream, chunk_size, check_size=True):
            # check_size is for the last bit of data that is smaller than a
            # chunk when data is compressed and the data sizes are
            # unpredictable.
            min_size = chunk_size
            if not check_size:
                min_size = 1
            while len(data_stream) >= min_size:
                chunk_data = data_stream[:chunk_size]
                # If compressing, will have to create new chunks later.
                chunks.append(ClientChunk.create(chunk_data, chunk_output_dir,
                                           prefix=chunk_prefix))
                data_stream = data_stream[chunk_size:]
                if chunk_sizes:
                    # next chunk size may be different
                    chunk_size = chunk_sizes.pop(0)
            return (data_stream, chunk_size)

        while f.tell() < file_size:
            data = f.read(CHUNK_SIZE_MAX)
            if compress:
                data = compressor.compress(data)
            if encrypt_key:
                data = encryptor.update(data)
                assert not encryptor.final()
            data_stream += data
            data_stream_len = len(data_stream)
            logger.debug('data stream length: %s' % data_stream_len)
            (data_stream, chunk_size) = chunk_stream(data_stream, chunk_size)
        # process data not chunked yet
        logger.debug('%s bytes left over' % len(data_stream))
        if compress:
            # may have compressed data left.
            flushed_data = compressor.flush()
            if flushed_data:
                logger.debug(
                    'another %s bytes of flushed data' % len(flushed_data))
                if encrypt_key:
                    flushed_data = encryptor.update(flushed_data)
                    assert not encryptor.final()
                data_stream += flushed_data
        if data_stream:
            (data_stream, chunk_size) = chunk_stream(data_stream, chunk_size,
                                                     False)
        assert not chunk_sizes
        f.close()
        # finished initial data chunking.
        new_size = sum((c.size - 4) for c in chunks)
        if not compress:
            emsg = ('original size was %s. expected new size to be '
                    '%s, but it is %s')
            expected_size = file_size
            if encrypt_key:
                expected_size = file_size + len(esalt) + len(iv)
            emsg = emsg % (file_size, expected_size, new_size)
            assert expected_size == new_size, emsg
        else:
            # must reorganize the chunks.
            new_chunks = []
            chunk_sizes = calc_chunk_sizes(new_size)
            # just replace the old chunk with the new one.
            data_stream = ''
            for chunk_size in chunk_sizes:
                # read the old chunks until there is enough to write.
                while len(data_stream) < chunk_size:
                    old_chunk = chunks.pop(0)
                    data_stream += old_chunk.read(raw=True)[:-4]
                    # free up the space
                    os.unlink(old_chunk.file_path)
                    # small files will not fill a chunk
                    if not chunks:
                        break
                chunk_data = data_stream[:chunk_size]
                new_chunks.append(ClientChunk.create(chunk_data, chunk_output_dir))
                data_stream = data_stream[chunk_size:]
            chunks = new_chunks
            # There should not be anything left over.
            assert not data_stream
        # size for comparison
        size_ratio = 1.0 * new_size / file_size
        logger.debug('new size (combined chunks) is %s bytes' % new_size)
        logger.debug('size ratio is %f' % size_ratio)
        logger.debug('split file into %s chunks' % len(chunks))
        return chunks

def combine_chunks(chunks, output_path, decompress=False, encrypt_key=None):
    """rebuild the original file from chunks

    """

    msg = 'combining %s chunks' % len(chunks)
    logger.info(msg)

    salt_length = 0
    key_length = 0
    if encrypt_key:
        if encrypt_key.binary_salt:
            salt_length = len(encrypt_key.binary_salt)
            assert salt_length == 16, salt_length
        key_length = len(encrypt_key.binary_key)
        assert key_length == 16, key_length
    f = open(output_path, 'wb')
    if decompress:
        decompressor = zlib.decompressobj()
    if encrypt_key:
        # salt, then iv
        iv = chunks[0].read(byte_range=[salt_length, salt_length + key_length])
        decryptor = Cipher(
            CIPHER_MODE, encrypt_key.binary_key, iv, CIPHER_DECODE
        )
    # sort out any parity chunks
    parity_chunks = []
    while chunks[-1].parity:
        parity_chunks.insert(0, chunks.pop())
    if parity_chunks and has_par2():
        cwd1 = os.getcwd()
        os.chdir(os.path.dirname(parity_chunks[0].file_path))
        # The files have to end in .par2 to work.
        for parity_chunk in parity_chunks:
            new_name = '%s.%s' % (parity_chunk.filename, 'par2')
            os.rename(parity_chunk.filename, new_name)
            parity_chunk.file_path = os.path.join(
                os.path.dirname(parity_chunk.file_path), new_name)
        # It won't recognize them by name, so put them on the command line.
        par2_repair([p.filename for p in parity_chunks])
        os.chdir(cwd1)
    for (i, chunk) in enumerate(chunks):
        chunk.verify_checksum()
        if i == 0 and encrypt_key:
            chunk_size = chunk.size
            if encrypt_key.binary_salt:
                # strip salt and IV
                data = chunk.read(
                    byte_range=[len(encrypt_key.binary_key) + \
                                len(encrypt_key.binary_salt),
                                chunk.size-4]
                )
            else:
                # skip the IV
                data = chunk.read(
                    byte_range=[len(encrypt_key.binary_key), chunk.size-4]
                )
        else:
            data = chunk.read()
        if encrypt_key:
            data = decryptor.update(data)
            assert not decryptor.final()
        if decompress:
            data = decompressor.decompress(data)
            assert not decompressor.unused_data
        f.write(data)
    f.close()
    logger.debug('file size is %s' % os.stat(output_path).st_size)

def add_parity(chunks):
    # add parity chunks to the list.
    firstwd = os.getcwd()
    chunk_path = os.path.dirname(chunks[0].file_path)
    os.chdir(chunk_path)
    try:
        if not has_par2():
            msg = ('Please install parchive from '
            'http://parchive.sourceforge.net/ '
            'to use parity files.')
            print msg
            return
        # stick to around 5 percent rounding up
        parity_count = int(round(len(chunks) * .07))
        if parity_count < 1:
            return
        logger.debug('producing %s parity chunks' % parity_count)
        chunk_sizes = [c.size for c in chunks]
        chunk_sizes.sort(reverse=True)
        # parity block size (smallest unit)
        block_size = chunk_sizes[0]
        # block size must be a multiple of 4
        while block_size % 4:
            block_size += 1
        logger.debug('block size is %s' % block_size)
        # Because the block size is one chunk, the number of blocks needed is
        # just the number of parity chunks we want.
        blocks_needed = parity_count
        par2_create(block_size, blocks_needed, parity_count)
        for filename in os.listdir('.'):
            if filename.endswith('par2'):
                chunk = ClientChunk.create(open(filename, 'rb').read(), chunk_path)
                chunk.parity = True
                chunks.append(chunk)
                os.unlink(filename)
    finally:
        os.chdir(firstwd)

def append_checksum(file_path):
    """append crc32 checksum to file"""

    cksum = calc_file_crc32(file_path)
    f = open(file_path, 'ab')
    f.write(struct.pack('<I', cksum))
    f.close()

def calc_chunk_sizes(data_size, min_chunk_size=CHUNK_SIZE_MIN - 4,
                     tgt_chunk_size=CHUNK_SIZE_TGT - 4,
                     max_chunk_size=CHUNK_SIZE_MAX - 4):
    """Figure out the best chunk size

    subtract 4 to leave room for the 4 byte checksum

    """
    logger.debug('data size is %s' % data_size)
    logger.debug('calculating chunk sizes')
    if data_size < min_chunk_size:
        return [min_chunk_size]
    elif data_size  <= tgt_chunk_size:
        return [data_size]
    # so now, we're only dealing with sizes > target size
    chunk_count = 1
    direction = 'up'
    changed_direction = False
    while 1:
        chunk_size = data_size * 1.0 / chunk_count
        margin = abs(tgt_chunk_size - chunk_size)
        if chunk_size == tgt_chunk_size:
            return [tgt_chunk_size,] * chunk_count
        elif changed_direction:
            if margin >= last_margin:
                chunk_count = last_chunk_count
            break
        elif chunk_size >= max_chunk_size:
            if direction == 'down':
                changed_direction = True
            direction = 'up'
            last_margin = margin
            last_chunk_count = chunk_count
        elif chunk_size <= min_chunk_size:
            if direction == 'up':
                changed_direction = True
            direction = 'down'
            last_margin = margin
            last_chunk_count = chunk_count
        else:
            last_margin = margin
            last_chunk_count = chunk_count
            if tgt_chunk_size < chunk_size < max_chunk_size and \
                                                        direction == 'down':
                # a little bigger than we'd like (need more pieces)
                direction = 'up'
                changed_direction = True
            elif min_chunk_size <= chunk_size < tgt_chunk_size and \
                                                        direction == 'up':
                # a bit too small (try fewer pieces)
                direction = 'down'
                changed_direction = True
        if direction == 'up':
            chunk_count += 1
        elif direction == 'down':
            chunk_count -= 1

    # Create the list of chunk sizes. Spread out the rounding difference among
    # the chunks so that they're close to the same size.
    chunk_size_raw = data_size * 1.0 / chunk_count
    logger.debug('unrounded chunk size is %s ' % chunk_size_raw)
    chunk_size = int(round(chunk_size_raw))
    logger.debug('rounded chunk size is %s' % chunk_size)
    total_round_diff = data_size - chunk_size * chunk_count
    msg = '%s rounded bytes to distribute among %s chunks'
    logger.debug(msg % (total_round_diff, chunk_count))
    # Round it to a full byte.  If it's negative, round down because rounding
    # up will take away too many chunks.
    if total_round_diff < 0:
        total_round_diff = int(math.floor(total_round_diff))
    else:
        total_round_diff = int(math.ceil(total_round_diff))
    round_diff_sum = total_round_diff
    chunk_sizes = []
    for i in range(chunk_count):
        if round_diff_sum > 0:
            this_chunk_size = chunk_size + 1
            round_diff_sum -= 1
        elif round_diff_sum < 0:
            this_chunk_size = chunk_size - 1
            round_diff_sum += 1
        else:
            this_chunk_size = chunk_size
        chunk_sizes.append(this_chunk_size)
    assert data_size == sum(chunk_sizes), '%s, %s' (data_size,
                                                    sum(chunk_sizes))
    return chunk_sizes

def par2_create(block_size, blocks_needed, parity_count):
    logger = logging.getLogger('scatterbytes.chunk.par2')
    cmd = ['par2create', '-s%s' % block_size, '-c%s' % blocks_needed,
               '-n%s' % parity_count, '-u', 'p.par2', '*']
    # for now, don't bother intercepting stdout/stderr
    subprocess.check_call(cmd)
    os.unlink('p.par2')

def par2_repair(parfile_names):
    logger = logging.getLogger('scatterbytes.chunk.par2')
    cmd = ['par2', 'repair']
    cmd.extend(parfile_names)
    # for now, don't bother intersepting stdout/stderr
    subprocess.check_call(cmd)

# thanks jimmyg.org

def whereis(program):
    for path in os.environ.get('PATH', '').split(':'):
        if os.path.exists(os.path.join(path, program)) and \
                            not os.path.isdir(os.path.join(path, program)):
            return os.path.join(path, program)
    return None

def has_par2():
    return whereis('par2')
