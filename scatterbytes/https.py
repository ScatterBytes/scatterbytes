"""HTTPS functionality

"""

import sys
import socket
import httplib
from urlparse import urlparse
import logging
import SocketServer
from M2Crypto import m2
from M2Crypto import SSL
from M2Crypto.SSL.Checker import Checker
from .crypt import Certificate
from . import __version__ as VERSION

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 20


class ClientSideChecker(Checker):

    def __call__(self, peerCert, host=None):
        # do not check host
        return Checker.__call__(self, peerCert, None)


class HTTPConnection(httplib.HTTPConnection):

    def __init__(self, host, port=None, strict=None, timeout=DEFAULT_TIMEOUT,
                 source_address=('', 0)):
        logger.debug(
            'creating a connection with source %s' % str(source_address)
        )
        args = [self, host, port, strict]
        kwargs = dict(timeout=timeout)
        if sys.version_info[1] == 6:
            logger.debug('Python 2.6 does not accept source_address')
            self.source_address = source_address
        else:
            kwargs['source_address'] = source_address
        httplib.HTTPConnection.__init__(*args, **kwargs)
        self._default_headers = {
            'Connection' : 'close',
            'User-Agent' : 'ScatterBytes Client %s' % VERSION,
        }

    def request(self, method, url, body=None, headers=None):
        # update default headers
        # encode strings as ascii
        method = str(method)
        url = str(url)
        new_headers = headers
        if new_headers is None:
            new_headers = {}
        headers = self._default_headers.copy()
        headers.update(new_headers)
        if isinstance(headers, list):
            headers = dict(headers)
        for (k, v) in headers.items():
            del headers[k]
            headers[str(k)] = str(v)
        httplib.HTTPConnection.request(self, method, url, body, headers)


class HTTPSConnection(HTTPConnection):
    """SSL connection with a timeout and bindable address.

    The current M2Crypto version doesn't use the new timeout and
    source_address introduced in 2.6.

    """

    def __init__(self, host, port=None, strict=None, timeout=DEFAULT_TIMEOUT,
                 source_address=('', 0), ssl_context=None):
        assert ssl_context
        self.ssl_ctx = ssl_context
        self.session = None
        self._timeout = timeout
        HTTPConnection.__init__(
            self, host, port, strict, source_address = source_address
        )

    def connect(self):
        sock = SSL.Connection(self.ssl_ctx)
        if self.source_address != ('', 0):
            sock.bind(self.source_address)
        # timeout doesn't work - use M2Crypto timeout on connect
        if self._timeout:
            # convert to microseconds
            m2_timeout = SSL.timeout(
                # set minimum of 1 microsecond
                microsec=(int(self._timeout * 1000) or 1)
            )
            sock.set_socket_read_timeout(m2_timeout)
            sock.set_socket_write_timeout(m2_timeout)
        sock.set_post_connection_check_callback(ClientSideChecker())
        self.sock = sock
        if self.session:
            sock.set_session(self.session)
        # While using an unreliable connection, I've seen it fail with
        # unexpected eof. Possibly check for SSLError and retry.
        # First attempt at this resulted in Transport endpoint is already
        # connected errors.
        # The SSL version of connect will setup SSL and check the certificate.
        try:
            sock.connect((self.host, self.port))
        except:
            emsg = 'connection to %s:%s failed' % (self.host, self.port)
            logger.error(emsg)
            raise

    def get_session(self):
        return self.sock.get_session()

    def set_session(self, session):
        self.session = session


def create_connection(url=None, host=None, port=None, strict=None,
                      timeout=DEFAULT_TIMEOUT, source_address=('', 0),
                                                        ssl_context=None):
    """factory to create HTTPConnection or HTTPSConnection"""
    assert url or host
    if url:
        o = urlparse(url)
        host = o.hostname
        port = o.port
        if o.scheme == 'https':
            conn_class = HTTPSConnection
        else:
            conn_class = HTTPConnection
    else:
        if ssl_context:
            conn_class = HTTPSConnection
        else:
            conn_class = HTTPConnection
    args = [host, port, strict, timeout, source_address]
    if conn_class == HTTPSConnection:
        args.append(ssl_context)
    return conn_class(*args)


class HandlerLoggingMixIn(object):

    def build_request_logger(self):

        # format
        fmt = '%(asctime)s: %(message)s'

        logger = logging.Logger('scatterbytes_https_server')
        formatter = logging.Formatter(fmt=fmt)
        file_path = getattr(self.server, 'requests_log_path', None)
        if file_path is None:
            # stdout handler
            handler = logging.StreamHandler(sys.stdout)
        else:
            handler = logging.RotatingFileHandler(file_path, maxBytes=2**20)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        self.request_logger = logger

    def log_message(self, format, *args):
        if not hasattr(self, 'request_logger'):
            self.build_request_logger()
        msg = "%s - - [%s] %s\n" % (self.address_string(),
                                    self.log_date_time_string(),
                                    format % args)
        self.request_logger.info(msg)


class HTTPServer(SocketServer.TCPServer):

    def __init__(self, server_address, RequestHandlerClass,
                                                    bind_and_activate=True):
        SocketServer.BaseServer.__init__(self, server_address,
                                         RequestHandlerClass)
        self._create_socket()
        if bind_and_activate:
            self.server_bind()
            self.server_activate()
        logger.debug('created server bound to %s' % str(server_address))

    def _create_socket(self):
        self.socket = socket.socket(self.address_family, self.socket_type)
        # this allows rebind after shutdown
        # m2 does this
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def process_request(self, request, client_address):
        logger.debug('handling request')
        try:
            self.finish_request(request, client_address)
            logger.debug('shutdown request')
            self.shutdown_request(request)
        except Exception as e:
            logger.debug('error occurred')
            self.handle_error(request, client_address, e)
            self.shutdown_request(request)

    def handle_error(self, request, client_address, error=None):
        if error:
            emsg = "%s - %s" % (str(error), client_address)
            logger.error(emsg, exc_info=True)
        else:
            logger.debug('handle_error called with no error argument.')
            logger.debug('%s, %s' % (request, client_address))
            logger.error('traceback', exc_info=True)


class HTTPSServer(HTTPServer):
    """HTTPS Server

    By default, it listens on all interfaces.

    """

    def __init__(self, server_address, RequestHandlerClass, ssl_context,
                                                    bind_and_activate=True):
        ssl_context.set_session_cache_mode(m2.SSL_SESS_CACHE_BOTH)
        self.ssl_ctx = ssl_context
        HTTPServer.__init__(self, server_address, RequestHandlerClass,
                                                        bind_and_activate)

    def _create_socket(self):
        self.socket = SSL.Connection(self.ssl_ctx)

    def finish_request(self, request, client_address):
        # make the client cert available
        cert = Certificate(
            pem_string=request.get_peer_cert().as_pem()
        )
        request.client_cert_info = {
            'CN' : cert.CN,
            'O' : cert.O,
            'OU' : cert.OU,
            'serial_number' : cert.serial_number
        }
        logger.debug('cert info: %s' % str(request.client_cert_info))
        HTTPServer.finish_request(self, request, client_address)

    def finish(self):
        # parent flushes wfile and closes both wfile and rfile
        HTTPServer.finish(self)
        request = self.request
        if request is not None:
            request.set_shutdown(
                SSL.SSL_RECEIVED_SHUTDOWN | SSL.SSL_SENT_SHUTDOWN
            )
            request.close()


class ThreadedHTTPServer(SocketServer.ThreadingMixIn, HTTPServer):
    """multi-threaded HTTP Server

    This is a multi-threaded HTTP server.

    By default, it listens on all interfaces.

    """

    pass


class ThreadedHTTPSServer(SocketServer.ThreadingMixIn, HTTPSServer):
    """multi-threaded HTTPS Server

    This is a multi-threaded HTTPS server.

    By default, it listens on all interfaces.

    """

    pass
