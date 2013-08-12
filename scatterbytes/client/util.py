import os
import datetime
import threading

FLAGS = {
    'compressed' : 2**1,
    'encrypted'  : 2**2,
    'parity'     : 2**3 
}

def create_flags(compressed=False, encrypted=False, parity=False):

    flags = 0
    if compressed:
        flags = flags | FLAGS['compressed']
    if encrypted:
        flags = flags | FLAGS['encrypted']
    if parity:
        flags = flags | FLAGS['parity']
    return flags

def read_flags(flags):
    flag_info = {}
    for (flag_name, flag_value) in FLAGS.items():
        if flags & flag_value:
            flag_info[flag_name] = True
        else:
            flag_info[flag_name] = False
    return flag_info

class ChunkTransferLog(object):

    name = 'changeme.log'

    def __init__(self, dir_path, name=None):
        if name is None:
            name = self.name
        file_path = os.path.join(dir_path, name)
        self.dir_path = dir_path
        self.file_path = file_path
        self.lock = threading.Lock()
        # file is not opened until first write
        self.log_file = None

    def append(self, msg):
        if self.log_file is None:
            file_path = self.file_path
            if os.path.exists(file_path):
                self.log_file = open(file_path, 'ab')
            else:
                self.log_file = open(file_path, 'wb')
        with self.lock:
            self.log_file.write('%s\n' % msg)

    def fsync(self):
        if self.log_file is None:
            return
        with self.lock:
            self.log_file.flush()
            os.fsync(self.log_file.fileno())

    def close(self):
        if self.log_file is not None:
            self.log_file.close()
