""" test usage of m2 httplib

tests assumptions about how m2crypto's httplib works

"""

import time
import logging
import unittest
import threading
from BaseHTTPServer import BaseHTTPRequestHandler
from M2Crypto import m2
from M2Crypto import SSL
from M2Crypto import httpslib
from M2Crypto.SSL.Checker import Checker
from M2Crypto.SSL.SSLServer import SSLServer
from . import util as testutil
from . import ssl
from . import test_https_common

logger = logging.getLogger(__name__)

logging.getLogger().setLevel(logging.DEBUG)


def setup():
    test_https_common.setup()
    testutil.create_tmp_directory()


def teardown():
    testutil.remove_tmp_directory()

CA_CERT_PATH = '/home/randall/tmp/sb_cache/ssl/ca_root/cert.pem'

HOSTNAME = '127.0.0.1'
PORT = 9987


class SBChecker(Checker):

    def __init__(self, *args, **kwargs):
        Checker.__init__(self, *args, **kwargs)

    def __call__(self, peerCert, host=None):
        # do not verify hostname
        return Checker.__call__(self, peerCert, None)

SSL.Connection.clientPostConnectionCheck = SBChecker()


class RequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        logger.info('called do_GET')
        msg = "<html><body>hello world</body></html>"
        msg = "<html>%s</html>" % \
            self.request.get_peer_cert().get_subject().as_text()
        self.send_response(200)
        self.send_header("Content-Type", 'text/html')
        self.send_header("Content-Length", len(msg))
        self.end_headers()
        self.wfile.write(msg)

    def log_message(self, fmt, *args):
        # don't want messages going to stderr
        print fmt % args


def get_session_key(sess):
    for l in sess.as_text().split('\n'):
        if l.lstrip().startswith('Master'):
            return l.strip()


def make_context(mode='client'):

    ca_cert_path = ssl.get_cert_path('ca_root')
    if mode == 'client':
        cert_path = ssl.get_cert_path('test_client_node')
        key_path = ssl.get_key_path('test_client_node')
    else:
        cert_path = ssl.get_cert_path('test_server_node')
        key_path = ssl.get_key_path('test_server_node')
    ctx = SSL.Context('tlsv1')
    ctx.set_session_id_ctx('ScatterBytes')
    ctx.load_cert_chain(cert_path, key_path)
    ctx.load_verify_locations(ca_cert_path)
    ctx.load_client_ca(ca_cert_path)
    if mode == 'client':
        logger.info('using client context')
        ctx.set_verify(SSL.verify_peer, 2)
        ctx.set_session_cache_mode(m2.SSL_SESS_CACHE_CLIENT)
    else:
        ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 2)
        ##ctx.set_verify(SSL.verify_peer, 2)
        ctx.set_session_cache_mode(m2.SSL_SESS_CACHE_SERVER)
    return ctx


def start_server():
    ctx = make_context('server')
    server_address = (HOSTNAME, PORT)
    server = SSLServer(server_address, RequestHandler, ctx)
    t = threading.Thread(target=server.serve_forever)
    t.start()
    return (t, server)


def stop_server(server_thread, server):
    logger.info('stopping server')
    t_stop = threading.Thread(target=server.shutdown)
    t_stop.start()
    t_stop.join()
    logger.info('joining server')
    server_thread.join()


class ResumeSessionTestCase(unittest.TestCase):

    """test TLS session resume

    """

    def setUp(self):
        # start up the server
        (server_thread, server) = start_server()
        self.server_thread = server_thread
        self.server = server
        # give the server time to start
        time.sleep(1)

    def test_resume(self):
        ctx = make_context('client')
        master_key_id_prev = None
        sess = None
        for i in xrange(10):
            try:
                con = httpslib.HTTPSConnection(HOSTNAME, PORT, ssl_context=ctx)
                if sess is None:
                    con.request('GET', '/')
                    sess = con.get_session()
                    ctx.add_session(sess)
                else:
                    con.set_session(sess)
                    con.request('GET', '/')
                    sess = con.get_session()
                master_key_id = get_session_key(sess)
                if master_key_id_prev:
                    self.assertEqual(master_key_id, master_key_id_prev)
                master_key_id_prev = master_key_id
                # close does nothing
                del con
            except Exception:
                raise

    def tearDown(self):
        stop_server(self.server_thread, self.server)
