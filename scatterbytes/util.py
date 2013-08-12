import os
import re
import sys
import math
import string
import base64
import logging
import datetime
import threading
from scatterbytes.errors import SBError

DT = datetime.datetime


logger = logging.getLogger(__name__)

# define LOG_LEVEL to be easily read by others
LOG_LEVEL = logging.INFO
_LOG_LEVEL_LOCK = threading.Lock()


class FamilyThreadMixIn(object):
    """parent aware thread mix-in"""

    def set_parent(self):
        "call this in init"
        self.parent_thread = threading.current_thread()

    def is_childof(self, thread):
        "is this thread is a child of thread given as argument"
        t = self.parent_thread
        while 1:
            if t == thread:
                return True
            elif hasattr(t, 'parent_thread'):
                t = t.parent_thread
            else:
                return False


class FamilyThread(threading.Thread, FamilyThreadMixIn):
    """parent aware thread

    use this in place of Thread

    """

    def __init__(self, *args, **kwargs):
        self.set_parent()
        threading.Thread.__init__(self, *args, **kwargs)


def setup_logging(config=None, stdout=False, verbosity=None):
    global LOG_LEVEL
    root_logger = logging.getLogger()
    # clear existing handlers
    for handler in root_logger.handlers:
        root_logger.removeHandler(handler)
    # setup logging
    if stdout:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(message)s'))
        root_logger.addHandler(handler)
    root_logger.addHandler(create_default_logging_handler(config))
    debug = False
    if verbosity is None:
        debug = config.get('debug')
    elif verbosity > 1:
            debug = True
    if debug:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO
    # environment will override this
    if os.environ.get('SB_LOGGING_LEVEL') in ('INFO', 'DEBUG'):
        logging_level = os.environ.get('SB_LOGGING_LEVEL')
    root_logger.setLevel(logging_level)
    with _LOG_LEVEL_LOCK:
        LOG_LEVEL = logging_level
    root_logger.debug('initialized logger at level %s' % logging_level)
    logger.debug('debug test message')


def create_default_logging_handler(config):
    log_filepath = config.log_path
    handler = logging.handlers.RotatingFileHandler(
        log_filepath, maxBytes=10 ** 6, backupCount=10
    )
    fmt = '%(asctime)s: %(levelname)s : %(name)s : %(message)s'
    formatter = logging.Formatter(fmt)
    handler.setFormatter(formatter)
    return handler


class RequestsLogFilter(logging.Filter):
    """filter HTTPS Requests"""

    def filter(self, record):
        if record.levelno == 19:
            return True
        return False


def create_requests_logging_handler(config):
    log_filepath = config.requests_log_path
    handler = logging.handlers.RotatingFileHandler(
        log_filepath, maxBytes=10 ** 6, backupCount=10
    )
    fmt = '%(message)s'
    formatter = logging.Formatter(fmt)
    handler.setFormatter(formatter)
    handler.addFilter(RequestsLogFilter())
    return handler


def get_available_storage(storage_path):
    "number of megabytes available in storage_path"
    if not os.path.exists(storage_path):
        return 0
    if not sys.platform.startswith('win'):
        s = os.statvfs(storage_path)
        bytes = s.f_bavail * s.f_frsize
        mbytes = int(bytes / 10 ** 6)
        return mbytes
    else:
        # Thanks stackoverflow.
        import ctypes
        free_bytes = ctypes.c_ulonglong(0)
        ctypes.windll.kernel32.GetDiskFreeSpaceExW(
            ctypes.c_wchar_p(storage_path), None, None,
            ctypes.pointer(free_bytes)
        )
        bytes = free_bytes.value
    mbytes = bytes / 10 ** 6
    return mbytes


def b32encode(input_bytes):
    "encode and strip padding"
    return base64.b32encode(input_bytes).rstrip('=')


def b32decode(b32_data):
    "restore padding and decode"
    b32_size = int(math.ceil(len(b32_data) / 8.0) * 8)
    return base64.b32decode(b32_data.ljust(b32_size, '='))


def b64encode(input_bytes):
    "encode and strip padding"
    return base64.b64encode(input_bytes).rstrip('=')


def b64decode(b64_data):
    "restore padding and decode"
    b64_size = int(math.ceil(len(b64_data) / 4.0) * 4)
    return base64.b64decode(b64_data.ljust(b64_size, '='))

# http://stackoverflow.com/questions/561486/\
# how-to-convert-an-integer-to-the-shortest-url-safe-string-in-python

B64_CHARSET = string.ascii_uppercase + string.ascii_lowercase + \
    string.digits + '+/'
B64_CHARSET_REVERSE_MAP = dict((c, i) for (i, c) in enumerate(B64_CHARSET))
B64_BASE = len(B64_CHARSET)


def base10_to_base64(base10_value):
    """change base from 10 to 64"""
    s = []
    n = base10_value
    while True:
        (n, r) = divmod(n, B64_BASE)
        s.append(B64_CHARSET[r])
        if n == 0:
            break
    return ''.join(reversed(s))


def base64_to_base10(base64_value):
    s = base64_value
    n = 0
    for c in s:
        n = n * B64_BASE + B64_CHARSET_REVERSE_MAP[c]
    return n

B32_CHARSET = string.ascii_uppercase + ''.join(map(str, range(2, 8)))
B32_CHARSET_REVERSE_MAP = dict((c, i) for (i, c) in enumerate(B32_CHARSET))
B32_BASE = len(B32_CHARSET)


def base10_to_base32(base10_value):
    """change base from 10 to 32"""
    s = []
    n = base10_value
    while True:
        (n, r) = divmod(n, B32_BASE)
        s.append(B32_CHARSET[r])
        if n == 0:
            break
    return ''.join(reversed(s))


def base32_to_base10(base32_value):
    s = base32_value
    n = 0
    for c in s:
        n = n * B32_BASE + B32_CHARSET_REVERSE_MAP[c]
    return n


def base16_to_base32(base16_value):
    base10_value = int(base16_value, 16)
    return base10_to_base32(base10_value)


def base32_to_base16(base32_value):
    base10_value = base32_to_base10(base32_value)
    return hex(base10_value)[2:-1]


class ControlNodeTime(object):

    """helps keep time with control node

    keeps track of offset between control node and client/storage nodes

    """

    def __init__(self):
        self.lock = threading.Lock()

    def update(self, server_ts):
        with self.lock:
            self.offset = datetime.datetime.utcnow() - server_ts

    def utcnow(self):
        with self.lock:
            if hasattr(self, 'offset') and self.offset:
                return datetime.datetime.utcnow() - self.offset
            else:
                return datetime.datetime.utcnow()

control_node_time = ControlNodeTime()


def get_utc_datetime():
    " Get the current UTC date and time, possibly compensating for drift."
    return control_node_time.utcnow()


def datetime_to_string(dt=None):
    if not dt:
        dt = get_utc_datetime()
    return dt.isoformat()

datetime_re = re.compile(
    r'(\d{4})-(\d{2})-(\d{2})(?=T(\d{2}):(\d{2}):(\d{2})(?=.(\d+))?)?'
)


def datetime_from_string(dt_str):
    if dt_str:
        match = datetime_re.match(dt_str)
        if match:
            g = filter(None, list(match.groups()))
            if len(g) < 4:
                return datetime.date(*map(int, g))
            else:
                return DT(*map(int, g))
    return None


class LimitedFileReader(object):

    """file-like object that only reads to a predetermined byte

    """

    def __init__(self, f, byte_start, byte_end):
        self.f = f
        file_size = os.fstat(f.fileno()).st_size
        self.file_size = file_size
        if byte_end == 0:
            byte_end = self.file_size
        if byte_end > file_size:
            raise SBError('invalid byte position')
        if byte_end < byte_start:
            raise SBError('invalid byte position')
        self.byte_start = byte_start
        self.byte_end = byte_end
        f.seek(byte_start)

    def read(self, size=None):
        f = self.f
        position = f.tell()
        # logger.debug('reading size %s' % size)
        # logger.debug('file size is %s' % file_size)
        # logger.debug('file position is %s' % position)
        if self.byte_end - position == 0:
            return None
        elif size is None:
            return f.read((self.byte_end - self.byte_start))
        elif size + position > self.byte_end:
            return f.read(self.byte_end - position)
        else:
            return f.read(size)

    def __getattr__(self, attr):
        return getattr(self.f, attr)
