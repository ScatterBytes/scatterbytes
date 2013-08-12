import os
import re
import time
import math
import Queue
import shutil
import hashlib
import logging
import datetime
import threading
import itertools
from .chunk import ClientChunk, combine_chunks
from .. import util
from .. import crypt
from . import util as client_util
from .util import ChunkTransferLog
from ..errors import DownloadError
from ..errors import TransferLogError
from ..compat import OrderedDict
 
logger = logging.getLogger(__name__)

JOB_ID_LOCK = threading.Lock()

JOB_ID_COUNTER = itertools.count()

def gen_job_id():
    with JOB_ID_LOCK:
        return JOB_ID_COUNTER.next()
            
def get_chunk_path(chunk_dir, chunk_sequence):
    file_name = 'chunk_%s' % str(chunk_sequence).zfill(9)
    chunk_path = os.path.join(chunk_dir, file_name)
    return chunk_path


class DownloadLog(ChunkTransferLog):

    name = 'downloads.log'
    dt_re = re.compile(
        r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})$'
    )

    @classmethod
    def _from_dt(cls, dt):
        return dt.strftime('%Y-%m-%dT%H:%M:%S')

    @classmethod
    def _to_dt(cls, dt_str):
        return datetime.datetime(
            *map(int, cls.dt_re.match(dt_str).groups())
        )

    def append_download_info(self, chunk_info, download_info):
        data = []
        data.append(str(chunk_info['chunk_sequence']))
        data.append(chunk_info['chunk_name'])
        data.append(chunk_info['chunk_hash'])
        data.append(str(chunk_info['chunk_size']))
        data.append(download_info['uri'])
        data.append(self._from_dt(download_info['expire_time']))
        data.append(download_info['signature'])
        data.append(self._from_dt(download_info['signature_ts']))
        msg = 'assigned %s' % ','.join(data)
        self.append(msg)

    def append_complete(self, chunk_sequence):
        self.append('completed %s' % chunk_sequence)

    @classmethod
    def read(cls, download_dir_path):
        return_data = {
            'chunks_complete' : [],
            'chunk_info' : {}
        }
        # first line should contain chunk info
        log_path = os.path.join(download_dir_path, cls.name)
        if not os.path.exists(log_path):
            return {}
        lines = open(log_path, 'rb').readlines()
        if not lines:
            return {}
        chunk_info = return_data['chunk_info']
        try:
            for line in lines:
                if line.startswith('completed'):
                    chunk_sequence = int(line.split()[1])
                    return_data['chunks_complete'].append(chunk_sequence)
                    continue
                (chunk_sequence, chunk_name, chunk_hash, chunk_size,
                uri, expire_time,
                signature, signature_ts) = line[9:].split(',')
                expire_time = cls._to_dt(expire_time)
                signature_ts = cls._to_dt(signature_ts)
                chunk_sequence = int(chunk_sequence)
                if chunk_sequence not in chunk_info:
                    chunk_info[chunk_sequence] = {
                        'chunk_sequence' : int(chunk_sequence),
                        'chunk_name' : chunk_name,
                        'chunk_hash' : chunk_hash,
                        'chunk_size' : int(chunk_size),
                        'download_info' : []
                    }
                download_info = {
                    'uri' : uri,
                    'expire_time' : expire_time,
                    'signature' : signature,
                    'signature_ts' : signature_ts,
                }
                # if it's expired, forget it
                now = util.get_utc_datetime()
                if expire_time < now + datetime.timedelta(minutes=5):
                    continue
                else:
                    chunk_info[chunk_sequence]['download_info'].append(
                        download_info
                    )
        except:
            raise TransferLogError('unable to read download log')
        return return_data
   

class DownloadWorkerThread(threading.Thread):
    
    def __init__(self, sn_proxy_creator, chunk_job_queue, 
                 chunk_job_complete_queue, chunk_job_failed_queue):
        threading.Thread.__init__(self)
        self.daemon = True
        self.sn_proxy_creator = sn_proxy_creator
        self.chunk_job_queue = chunk_job_queue
        self.chunk_job_complete_queue = chunk_job_complete_queue
        self.chunk_job_failed_queue = chunk_job_failed_queue
        self.shutdown_event = threading.Event()
        self.working_event = threading.Event()

    def run(self):
        while not self.shutdown_event.wait(.1):
            # responsiveness vs business tradeoff
            try:
                job = self.chunk_job_queue.get(False)
                logger.debug('got job %s from queue' % job)
            except Queue.Empty:
                logger.debug('job queue is empty')
                continue
            self.working_event.set()
            logger.debug('got download job to process')
            try:
                self.download_chunk_part(job)
            except Exception as e:
                self.chunk_job_failed_queue.put(job)
                logger.debug('job %s failed' % job['id'])
                logger.debug(str(e), exc_info=True)
                logger.error(str(e))
            finally:
                self.working_event.clear()

    @property
    def working(self):
        # TODO
        # Is an event needed here or is it safe to just use an attribute?
        return self.working_event.is_set()

    def shutdown(self):
        self.shutdown_event.set()

    def download_chunk_part(self, job):
        chunk_name = job['chunk_name']
        request = job['request']
        sig = request['signature']
        sig_ts = request['signature_ts']
        url = request['uri']
        expire_time = request['expire_time']
        (byte_start, byte_end) = job['byte_range']
        sn_proxy = self.sn_proxy_creator(url)
        msg = 'requesting %s, %s-%s, %s' % (
            chunk_name, byte_start, byte_end, byte_end - byte_start
        )
        logger.debug(msg)
        chunk_f = sn_proxy.retrieve_chunk(
            sig, sig_ts, expire_time, chunk_name, byte_start, byte_end
        )
        # go ahead and read the data so if there are problems, they will
        # occur here.
        with open(job['chunk_segment_path'], 'wb') as f:
            shutil.copyfileobj(chunk_f, f)
        expected_size = byte_end - byte_start
        received_size = os.stat(job['chunk_segment_path']).st_size
        if expected_size != received_size:
            emsg = "expected size: %s, actual size: %s" % (
                expected_size, received_size
            )
            raise DownloadError(emsg)
        self.chunk_job_complete_queue.put(job)
            

class SplitChunk(object):
    """Chunk split into segments for downloading.

    keeps state of downloaded parts for a chunk

    complete
        all segments downloaded and chunk is complete

    """

    # arbitrary min size
    min_segment_size =  100000

    def __init__(self, chunk_dir, chunk_info):
        """

        chunk_dir
            dir to the downloaded chunk to
        
        chunk_info
            information about the chunk given by the control node

        """
        
        self.chunk_dir = chunk_dir
        self.chunk_name = chunk_info['chunk_name']
        self.chunk_sequence = chunk_info['chunk_sequence']
        self.chunk_path = get_chunk_path(chunk_dir, self.chunk_sequence)
        self.chunk_size = chunk_info['chunk_size']
        self.chunk_info = chunk_info
        self.segments = []
        self.jobs = []

    @property
    def split_limit(self):
        """maximum segments a chunk should be split into"""
        min_size = 128 * 1000.0
        split_limit = int(
            math.floor(1.0 * self.chunk_size / self.min_segment_size)
        )
        # in case floor == 0
        return max(1, split_limit)

    @classmethod
    def _split(cls, chunk_size, split_limit, segment_count):
        """define segments for chunk"""
        segments = []
        if segment_count > split_limit:
            segment_count = split_limit
        assert split_limit > 0
        assert segment_count > 0
        segment_size = chunk_size / segment_count
        # any leftover bytes get tacked on
        if chunk_size % segment_count:
            segment_size += 1
        byte_start = 0
        while byte_start < chunk_size:
            byte_end = byte_start + segment_size
            # if the chunk doesn't divide evenly, last segment will be smaller
            if byte_end > chunk_size:
                byte_end = chunk_size
            segments.append((byte_start, byte_end))
            byte_start = byte_end
        size = sum(b[1] - b[0] for b in segments)
        assert size == chunk_size, (size, chunk_size)
        return segments

    def split(self, segment_count):
        """split chunk into even byte ranges"""
        chunk_size = self.chunk_size
        split_limit = self.split_limit
        segments = self._split(chunk_size, split_limit, segment_count)
        self.segments = segments

    @classmethod
    def _create_jobs(cls, chunk_dir, segments, chunk_info):
        segments.sort()
        requests = chunk_info['requests']
        assert len(segments) <= len(requests)
        jobs = []
        chunk_sequence = chunk_info['chunk_sequence']
        chunk_path = get_chunk_path(chunk_dir, chunk_sequence)
        for (i, segment) in enumerate(segments):
            request = requests[i]
            chunk_segment_path = chunk_path + '-segment-%s' % str(i).zfill(2)
            job = {
                'id' : gen_job_id(),
                'request' : request,
                'chunk_name' : chunk_info['chunk_name'],
                'chunk_segment_path' : chunk_segment_path,
                'byte_range' : segment,
                'complete' : False,
                'failed' : False,
                'attempts' : []
            }
            jobs.append(job)
        return jobs

    def create_jobs(self):
        requests = self.chunk_info['requests']
        snode_count = len(requests)
        logger.debug('creating jobs for chunk %s' % self.chunk_sequence)
        self.split(snode_count)
        logger.debug('segment_count is %s' % len(self.segments))
        jobs = self._create_jobs(
            self.chunk_dir, self.segments, self.chunk_info,
        )
        logger.debug('storage node count is %s' % snode_count)
        for job in jobs:
            job['split_chunk'] = self
        logger.debug('created %s jobs' % len(jobs))
        self.jobs.extend(jobs)
        # check segments
        segments_size = sum(j['byte_range'][1] - j['byte_range'][0] \
                                                        for j in self.jobs)
        assert self.chunk_size == segments_size, \
                                            (self.chunk_size, segments_size)
        return jobs

    def complete_job(self, job):
        assert job['byte_range'] in self.segments
        job['complete'] = True
        # if we have all segments, build the chunk
        self.segments.sort()
        complete_jobs = self.jobs_complete
        complete_jobs.sort(key=lambda x: x['byte_range'])
        if self.segments == [j['byte_range'] for j in complete_jobs]:
            # all done - assemble
            # sort by byte range
            chunk_path = get_chunk_path(self.chunk_dir, self.chunk_sequence)
            f = open(chunk_path, 'ab')
            logger.debug('assembling %s' % chunk_path)
            for job in complete_jobs:
                segment_path = job['chunk_segment_path']
                segment_size = os.stat(segment_path).st_size
                logger.debug('%s - %s' % (segment_path, segment_size))
                f.write(open(segment_path, 'rb').read())
            f.close()
            chunk = ClientChunk(self.chunk_path)
            chunk.verify_checksum()
            chunk.verify_hash(self.chunk_info['chunk_hash'])
            self.chunk_info['client_chunk'] = chunk
            self.chunk_info['complete'] = True

    @property
    def jobs_complete(self):
        return [j for j in self.jobs if j['complete']]

    @property
    def jobs_incomplete(self):
        return [j for j in self.jobs if not j['complete'] and not j['failed']]


class ThreadedDownloader(object):
    """downloads all chunks and recombines them

    file_info
        information about the file from the control node

    thread_count
        number of download threads to spawn

    output_path
        path to save the downloaded file

    download_dir
        directory where all downloaded files are stored. The downloaded file
        will be stored under a subdirectory using the volume name and a hash
        of the file name.

    chunk_download_dir
        dirctory where chunks for this specific download are stored -
        hash of the volume name and file name

    """

    sleep_period = 0.1

    def __init__(self, file_info, control_node_proxy,
                 snode_proxy_creator, thread_count, encrypt_passphrase,
                 output_path, download_dir):
        self.file_info = file_info
        self.control_node_proxy = control_node_proxy
        self.snode_proxy_creator = snode_proxy_creator
        self.thread_count = thread_count
        self.encrypt_passphrase = encrypt_passphrase
        self.output_path = output_path
        self.download_dir = download_dir
        self.chunk_download_dir = self.get_chunk_download_dir(
            download_dir, file_info['volume_name'], file_info['file_name']
        )
        if not os.path.exists(self.chunk_download_dir):
            os.makedirs(self.chunk_download_dir)
        self.download_log = DownloadLog(self.chunk_download_dir)
        # How the chunks are downloaded depends on how many threads we are
        # using and how many chunks the file has.
        self.chunks_per_request_max = 25
        # minimum queue size for making new chunk requests
        self.chunk_job_queue_min_size = 10
        # indicates that all jobs have completed successfully
        self.jobs_complete = False
        # need enough download nodes to keep all of the threads busy
        chunk_count = file_info['chunk_count']
        mirror_count = file_info['mirror_count']
        self.nodes_per_chunk = int(min(
            math.ceil(1.0 * thread_count / chunk_count), mirror_count + 1
        ))
        logger.debug('nodes per chunk: %s' % self.nodes_per_chunk)
        # the downloaded chunks
        # primary data structure for chunk information
        chunks = OrderedDict()
        for i in xrange(chunk_count):
            chunks[i] = {
                'chunk_name' : None,
                'chunk_hash' : None,
                'chunk_size' : None,
                'chunk_sequence' : i,
                'split_chunk' : None,
                'complete' : False,
                'requests' : [],
            }
        self.chunks = chunks
        self.worker_threads = []
        self.failed_jobs = []
        self.chunk_job_queue = Queue.Queue()
        self.chunk_job_complete_queue = Queue.Queue()
        self.chunk_job_failed_queue = Queue.Queue()

    @property
    def complete(self):
        ##split_chunks = [c['split_chunk'] for c in self.chunks.values()]
        ##print split_chunks
        ##for split_chunk in split_chunks:
        ##    if split_chunk:
        ##        print split_chunk.chunk_sequence, split_chunk.complete
        for chunk_info in self.chunks.values():
            if not chunk_info['complete']:
                return False
        return True

    def shutdown_workers(self):
        for worker_thread in self.worker_threads:
            worker_thread.shutdown()
           
    def process_queues(self):
        # completions
        queue = self.chunk_job_complete_queue
        while 1:
            try:
                job = queue.get(False)
                split_chunk = job['split_chunk']
                chunk_sequence = split_chunk.chunk_sequence
                chunk_info = self.chunks[chunk_sequence]
                job['complete'] = True
                job['attempts'].append(job['id'])
                split_chunk.complete_job(job)
                if chunk_info['complete']:
                    self.download_log.append_complete(
                        split_chunk.chunk_sequence
                    )
            except Queue.Empty:
                break
        # failures
        queue = self.chunk_job_failed_queue
        while 1:
            try:
                job = queue.get(False)
                job['failed'] = True
                job['attempts'].append(job['id'])
                self.failed_jobs.append(job)
            except Queue.Empty:
                break

    def handle_failed_jobs(self):
        def clone_job(old_job):
            new_job = old_job.copy()
            new_job['failed'] = False
            new_job['id'] = gen_job_id()
            old_job['split_chunk'].jobs.append(new_job)
            return new_job
        while self.failed_jobs:
            job = self.failed_jobs.pop(0)
            if len(job['attempts']) == 1:
                # try again
                logger.debug('reattempting job %s' % job['id'])
                self.chunk_job_queue.put(clone_job(job))
            else:
                # create a new job using a different storage node
                new_job = None
                logger.debug('scheduling to download from another snode')
                for other_job in job['split_chunk'].jobs[:]:
                    if other_job['failed']:
                        continue
                    if other_job['id'] not in job['attempts']:
                        new_job = clone_job(job)
                        new_job['request'] = other_job['request']
                        self.chunk_job_queue.put(new_job)
                        break
                if new_job is None:
                    raise DownloadError(
                        'all attempts to download chunk failed')
                # FIXME - handle reporting failures

    def update_chunk(self, chunk_info):
        chunk_sequence = chunk_info['chunk_sequence']
        chunk_record = self.chunks[chunk_sequence]
        chunk_record['chunk_name'] = chunk_info['chunk_name']
        chunk_record['chunk_size'] = chunk_info['chunk_size']
        chunk_record['chunk_hash'] = chunk_info['chunk_hash']
        if chunk_record['split_chunk'] is None:
            chunk_dir = self.chunk_download_dir
            chunk_record['split_chunk'] = SplitChunk(chunk_dir, chunk_record)
        chunk_record['requests'].extend(chunk_info['download_info'])

    @property
    def requests_complete(self):
        """do not make any more requests"""
        response = True
        for chunk_info in self.chunks.values():
            if not chunk_info['complete'] and not chunk_info['requests']:
                response = False
                break
        return response

    def request_chunks(self):
        if self.requests_complete:
            return
        chunks_per_request_max = self.chunks_per_request_max
        nodes_per_chunk = self.nodes_per_chunk
        chunk_job_queue = self.chunk_job_queue
        chunk_job_queue_min_size = self.chunk_job_queue_min_size
        # if the buffer is populated, don't request more
        job_buffer_size = chunk_job_queue.qsize()
        jobs_max = chunks_per_request_max * nodes_per_chunk
        if job_buffer_size > chunk_job_queue_min_size:
            return
        # figure out offset and limit
        chunk_limit = max(
            1,
            int((jobs_max - job_buffer_size) / nodes_per_chunk)
        )
        if len(self.chunks) < chunk_limit:
            chunk_limit = len(self.chunks)
        chunk_offset = 0
        for i in xrange(len(self.chunks)):
            sequence = i
            chunk_data = self.chunks[i]
            if not (chunk_data['complete'] or chunk_data['requests']):
                chunk_offset = sequence
                break
        # see if smaller limit is needed
        for sequence in xrange(chunk_offset + 1, len(self.chunks)):
            chunk_data = self.chunks[sequence]
            if chunk_data['requests']:
                # break here regardless - should't re-equest chunks
                if sequence - chunk_offset < chunk_limit:
                    chunk_limit = sequence - chunk_offset
                break
        logger.debug('offset: %s, limit: %s' % (chunk_offset, chunk_limit))
        volume_name = self.file_info['volume_name']
        file_name = self.file_info['file_name']
        response = self.control_node_proxy.request_chunks(
            volume_name, file_name, chunk_offset, chunk_limit, nodes_per_chunk
        )
        sequence = chunk_offset
        logger.debug('got response - queueing jobs')
        for chunk_record in response['chunk_info']:
            chunk_record['chunk_sequence'] = sequence
            self.update_chunk(chunk_record)
            self.log_control_node_response(chunk_record)
            # create jobs for this chunk
            split_chunk = self.chunks[sequence]['split_chunk']
            for job in split_chunk.create_jobs():
                # assign the job id
                self.chunk_job_queue.put(job)
                logger.debug('queued job %s' % job)
            sequence += 1
        logger.debug('all jobs are queued')

    def log_control_node_response(self, chunk_record):
        chunk_info = {
            'chunk_sequence' : chunk_record['chunk_sequence'],
            'chunk_name' : chunk_record['chunk_name'],
            'chunk_hash' : chunk_record['chunk_hash'],
            'chunk_size' : chunk_record['chunk_size'],
        }
        for download_info in chunk_record['download_info']:
            self.download_log.append_download_info(chunk_info, download_info)

    def clean_chunk_download_dir(self):
        "delete all partial downloads"
        if not os.path.exists(self.chunk_download_dir):
            return
        for name in os.listdir(self.chunk_download_dir):
            if name.endswith('log'):
                continue
            if 'segment' in name or not name.startswith('chunk'):
                os.unlink(os.path.join(self.chunk_download_dir, name))

    def process_log(self):
        try:
            log_data = DownloadLog.read(self.chunk_download_dir)
            if not log_data:
                return
            logger.info('attempting to resume download')
            chunks_complete = log_data['chunks_complete']
            for (chunk_sequence, chunk_info) in log_data['chunk_info'].items():
                self.update_chunk(chunk_info)
            for chunk_sequence in chunks_complete:
                chunk_dset = self.chunks[chunk_sequence]
                chunk_dset['complete'] = True
                split_chunk = chunk_dset['split_chunk']
                chunk_path = split_chunk.chunk_path
                chunk = ClientChunk(chunk_path)
                chunk.verify_checksum()
                chunk.verify_hash(chunk_dset['chunk_hash'])
                chunk_dset['client_chunk'] = chunk
            # delete any chunks not marked as completed
            for name in os.listdir(self.chunk_download_dir):
                if name.startswith('chunk'):
                    chunk_sequence = int(name.split('_')[1])
                    if chunk_sequence not in chunks_complete:
                        logger.debug('deleting chunk %s' % chunk_sequence)
                        os.unlink(os.path.join(self.chunk_download_dir, name))
            # for each incomplete split_chunk, create jobs
            for chunk_info in self.chunks.values():
                if not chunk_info['complete'] and chunk_info['requests']:
                    for job in chunk_info['split_chunk'].create_jobs():
                        self.chunk_job_queue.put(job)
            logger.info('resume initiated')
        except Exception as e:
            raise
            ##logger.info('cannot resume download')
            ##logger.error(str(e), exc_info=True)

    @classmethod
    def get_chunk_download_dir(cls, download_dir, volume_name, file_name):
        if not volume_name:
            volume_name = ''
        name = util.b32encode(
            hashlib.sha1(volume_name + file_name).digest()
        )
        download_dir = os.path.join(download_dir, name)
        return download_dir

    def download_chunks(self):
        # create download directory
        volume_name = self.file_info['volume_name']
        file_name = self.file_info['file_name']
        self.clean_chunk_download_dir()
        # check the log file
        self.process_log()
        # create thread pool
        for i in xrange(self.thread_count):
            t = DownloadWorkerThread(
                self.snode_proxy_creator, self.chunk_job_queue,
                self.chunk_job_complete_queue, self.chunk_job_failed_queue
            )
            t.start()
            self.worker_threads.append(t)
        try:
            while 1:
                # if all of the threads are busy, just wait
                logger.debug('processing queues')
                self.process_queues()
                logger.debug('done processing queues')
                if self.complete:
                    # all done
                    logger.debug('all done')
                    break
                elif self.failed_jobs:
                    logger.debug('handling failed jobs')
                    self.handle_failed_jobs()
                elif self.requests_complete:
                    # no more work to do - just waiting
                    logger.debug('requests complete - just waiting')
                    time.sleep(self.sleep_period)
                elif self.chunk_job_queue_min_size < \
                                                self.chunk_job_queue.qsize():
                    # plenty of jobs in the queue for now
                    logger.debug('plenty of queued jobs - waiting')
                    time.sleep(self.sleep_period)
                else:
                    logger.debug('requesting chunks')
                    self.request_chunks()
        finally:
            for t in self.worker_threads:
                t.shutdown()
                t.join()

    def download(self):
        volume_name = self.file_info['volume_name']
        file_name = self.file_info['file_name']
        msg = 'downloading %s from volume %s' % (file_name, volume_name)
        logger.info(msg)
        self.download_chunks()
        chunks = []
        for i in xrange(len(self.chunks)):
            split_chunk = self.chunks[i]['split_chunk']
            chunks.append(self.chunks[i]['client_chunk'])
        output_path = self.output_path
        flags = client_util.read_flags(self.file_info['flags'])
        encrypt_key = None
        if self.encrypt_passphrase:
            # create our key - need the salt, which is first 8 bytes
            salt = chunks[0].read(byte_range=[0, 8])
            encrypt_key = crypt.AESKey.create_pbkdf2(
                self.encrypt_passphrase, salt=salt
            )
        combine_chunks(
            chunks, self.output_path, flags['compressed'], encrypt_key
        )
