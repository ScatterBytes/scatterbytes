import os
import re
import sys
import time
import shutil
import logging
from ..crypt import Certificate
from ..util import FamilyThread
from ..util import setup_logging
from ..util import datetime_from_string
from .node import StorageNode
from .node import StorageNodeConfig
from ..errors import ConfigError
from ..jsonrpc import SSLRPCServer
from ..jsonrpc import ThreadedSSLRPCServer
from ..jsonrpc import RPCDispatcher
from ..jsonrpc import RPCRequestHandler
from ..jsonrpc import ControlNodeProxy
from ..jsonrpc import gen_storage_node_proxy_creator

logger = logging.getLogger(__name__)

PID_PATH = '/var/run/scatterbytes/scatterbytes-server.pid'


class ChunkFile(object):

    """Mimic a file object with read method.

    This is required to adapt the request handler's method for reading to the
    StorageNode.

    """

    max_chunk_size = 5 * 1000 ** 2

    def __init__(self, rfile, content_length):
        self.rfile = rfile
        self.position = 0
        self.content_length = content_length

    def read(self, size=None):
        rfile = self.rfile
        data = []
        content_length = self.content_length
        if size is None:
            while self.position < content_length:
                bytes_remaining = content_length - self.position
                chunk_size = min(bytes_remaining, self.max_chunk_size)
                data_read = rfile.read(chunk_size)
                self.position += len(data_read)
                data.append(data_read)
        else:
            read_to_pos = min(self.position + size, self.content_length)
            while self.position < read_to_pos:
                bytes_remaining = content_length - self.position
                chunk_size = min(bytes_remaining, self.max_chunk_size, size)
                data_read = rfile.read(chunk_size)
                self.position += len(data_read)
                data.append(data_read)
        if data is not None:
            return ''.join(data)


class StorageNodeRequestHandler(RPCRequestHandler):
    """Request handler adding GET and PUT handling for file transfers.

    """

    # No need to use compression - let SSL handle it.

    # match URL
    file_re = re.compile(r'^/sbfile/(C-[A-Z0-9]+)$')

    def do_GET(self):
        """Send all or part of a file."""
        auth = self.headers.get('x-sb-auth')
        auth_ts = datetime_from_string(self.headers.get('x-sb-auth-ts'))
        expire_time = datetime_from_string(
            self.headers.get('x-sb-expire-time')
        )
        byte_range = self.headers.get('bytes')
        cert_info = self.request.client_cert_info
        match = self.file_re.match(self.path)
        # send either 404 or 200
        if not match:
            logger.debug('%s not found' % self.path)
            self.send_error(404, "File not found")
            return
        elif match:
            (chunk_name, ) = match.groups()
            f_args = [cert_info, auth, auth_ts, expire_time, chunk_name]
            if byte_range:
                (byte_start, byte_end) = map(int, (byte_range.split('-')))
                # HTTP uses inclusive range - we do not.
                byte_end += 1
                f_args.extend([byte_start, byte_end])
            (f, file_size) = self.server.storage_node.retrieve_chunk(*f_args)
            msg = 'sending %s of size %s' % (chunk_name, file_size)
            logger.debug(msg)
        self.send_response(206)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(file_size))
        self.end_headers()
        logger.debug('sending data')
        shutil.copyfileobj(f, self.wfile)
        logger.debug('data sent')
        f.close()
        return

    def do_PUT(self):
        """Check and store a file."""

        logger.debug('got put request')
        logger.debug(str(self.headers.items()))
        cert_info = self.request.client_cert_info
        data_size = int(self.headers['content-length'])
        sig = self.headers.get('x-sb-sig')
        sig_ts = self.headers.get('x-sb-sig-ts')
        transfer_name = self.headers.get('x-sb-transfer-name')
        chunk_hash_salt = self.headers.get('x-sb-hash-salt')
        sig_ts = datetime_from_string(sig_ts)
        expire_time = self.headers.get('x-sb-expire-time')
        expire_time = datetime_from_string(expire_time)
        chunk_name = os.path.basename(self.path)
        chunk_file = ChunkFile(self.rfile, data_size)
        logger.debug('passing it off to storage node instance')
        try:
            response = self.server.storage_node.store_chunk(
                cert_info, sig, sig_ts, expire_time, transfer_name,
                chunk_name, chunk_hash_salt, chunk_file
            )
        except Exception, e:
            print 'error', e
            raise
        self.send_response(201)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)
        self.wfile.flush()
        self.connection.shutdown(1)

    def log_message(self, format, *args):
        (host, port) = self.client_address[:2]
        address = '%s:%s' % (host, port)
        msg = "%s - - [%s] %s\n" % (address, self.log_date_time_string(),
                                    format % args)
        logger.log(19, msg)

    def report_404(self):
        self.send_response(404)
        response = "No such page"
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)
        self.wfile.flush()
        self.connection.shutdown(1)


class StorageNodeSSLServer(SSLRPCServer):
    """single-threaded JSON-RPC Server for a storage node.

    """

    def __init__(self, storage_node, log_requests=True):
        self.storage_node = storage_node
        config = storage_node.config
        # for logging requests
        self.requests_log_path = config.requests_log_path
        listen_address = config.get('listen_address', section='network')
        listen_port = config.get('listen_port', section='network')
        logger.info('listening on: %s:%s' % (listen_address, listen_port))
        ssl_context = config.make_ssl_context()
        assert ssl_context is not None
        dispatcher = RPCDispatcher(self.storage_node)
        SSLRPCServer.__init__(
            self, (listen_address, listen_port), dispatcher, ssl_context,
            StorageNodeRequestHandler, log_requests
        )

    def shutdown(self):
        try:
            self.storage_node.shutdown()
        finally:
            logger.debug('shutting down JSON-RPC server')
            SSLRPCServer.shutdown(self)


class ThreadedStorageNodeSSLServer(ThreadedSSLRPCServer):
    """multi-threaded JSON-RPC Server for a storage node.

    """

    def __init__(self, storage_node, log_requests=True):
        self.storage_node = storage_node
        config = storage_node.config
        # for logging requests
        self.requests_log_path = config.requests_log_path
        listen_address = config.get('listen_address', section='network')
        listen_port = config.get('listen_port', section='network')
        logger.info('listening on: %s:%s' % (listen_address, listen_port))
        ssl_context = config.make_ssl_context()
        dispatcher = RPCDispatcher(self.storage_node)
        ThreadedSSLRPCServer.__init__(
            self, (listen_address, listen_port), dispatcher, ssl_context,
            StorageNodeRequestHandler, log_requests
        )

    def shutdown(self):
        try:
            self.storage_node.shutdown()
        finally:
            logger.debug('shutting down JSON-RPC server')
            ThreadedSSLRPCServer.shutdown(self)


StorageNodeServer = ThreadedStorageNodeSSLServer


def create_storage_node(control_node_proxy=None,
                        storage_node_proxy_creator=None,
                        config=None, verbosity=None):
    """factory for StorageNode

    unlike scatterbytes.storage.node.create_storage_node, this factory is
    json-rpc specific

    """
    if config is None:
        config = StorageNodeConfig.get_config()
    setup_logging(config, stdout=False, verbosity=verbosity)
    if control_node_proxy is None:
        control_node_proxy = ControlNodeProxy(config)
    if storage_node_proxy_creator is None:
        storage_node_proxy_creator = gen_storage_node_proxy_creator(config)
    return StorageNode(control_node_proxy, storage_node_proxy_creator, config)


def start_server(daemonize=True, config=None):
    import signal
    try:
        import daemon
        # called pidlockfile in standard debian distro
        try:
            import daemon.pidfile
        except ImportError:
            import daemon.pidlockfile
            daemon.pidfile = daemon.pidlockfile
    except ImportError:
        daemon = None
    import M2Crypto
    import M2Crypto.Rand
    if not config:
        config = StorageNodeConfig.get_config()

    def signal_handler(*args):
        logger.info('caught signal ... shutting down ...')
        server.shutdown()
        server_thread.join()
        M2Crypto.Rand.save_file(
            os.path.join(config.data_directory, 'randpool.dat')
        )
        M2Crypto.threading.cleanup()
        sys.exit(0)

    if daemonize:
        daemon_kwargs = {}
        pid_dir = os.path.dirname(PID_PATH)
        if not os.access(pid_dir, os.W_OK):
            # data directory should be writable
            pid_dir = config.data_directory
        emsg = "expected to be able to write %s" % pid_dir
        assert os.access(pid_dir, os.W_OK), emsg
        pid_path = os.path.join(pid_dir, 'scatterbytes-server.pid')
        daemon_kwargs['pidfile'] = daemon.pidfile.TimeoutPIDLockFile(pid_path)
        # make sure it's not running
        if os.path.exists(pid_path):
            raise OSError('PID file %s already exists' % pid_path)
        # get uid for username
        import pwd
        try:
            username = 'scatterbytes'
            uid = pwd.getpwnam(username).pw_uid
            if uid:
                daemon_kwargs['uid'] = uid
                daemon_kwargs['working_directory'] = \
                    os.path.expanduser('~%s' % username)
        except KeyError:
            uid = None
        daemon_kwargs['signal_map'] = {
            signal.SIGTERM: signal_handler,
        }
        context = daemon.DaemonContext(**daemon_kwargs)
        context.open()

    setup_logging(config)

    # The storage node will not initialize if it isn't registered.
    if not config.get('node_id'):
        logger.error('missing node_id')
        raise ConfigError('missing node_id')
    # check for expired certificate and delete it if expired.
    if os.path.exists(config.cert_path):
        cert = Certificate(filepath=config.cert_path)
        cert.check_expire()
    if not os.path.exists(config.cert_path) and \
            not config.get('recert_code'):
        logger.error('missing recert_code')
        raise ConfigError('missing recert_code')
    control_node_proxy = ControlNodeProxy(config)
    storage_node = create_storage_node(control_node_proxy, config=config)
    # seed random number generator
    seed_path = os.path.join(config.data_directory, 'randpool.dat')
    if os.path.exists(seed_path):
        M2Crypto.Rand.load_file(seed_path, -1)
    M2Crypto.threading.init()

    # first load the certificates using high retry count in case of outage
    storage_node.load_certificates(retries=100000, wait_time=30)

    server = ThreadedStorageNodeSSLServer(storage_node)

    server_thread = FamilyThread(target=server.serve_forever)
    server_thread.start()

    # Now that the https server is running, let the storage node daemon(s)
    # start.
    storage_node.startup()
    if not daemonize:
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
    # just wait until we're asked to exit
    # got to keep this process going for the signal handler to work
    while 1:
        time.sleep(.1)
