import time
import logging
import datetime
import unittest
import threading
from StringIO import StringIO
from .. import jsonrpc
from .util import make_http_message

logger = logging.getLogger(__name__)


def _timeit(f, pargs, iterations=1000):
    t1 = time.time()
    for i in xrange(iterations):
        response = f(*pargs)
    delta = time.time() - t1
    rate = iterations / float(delta)
    return (response, delta, rate)


def test_marshall():
    # request
    request_id = 1
    now = datetime.datetime.utcnow()
    d1 = 1
    d2 = 2.2
    method_name = 'doit'
    marshall_params = (request_id, method_name, [d1, d2, now])
    request = jsonrpc.marshall_request(*marshall_params)
    assert jsonrpc.unmarshall_request(request) == marshall_params
    # response
    error = jsonrpc.InternalError()
    json_data = jsonrpc.marshall_response(request_id, error=error)
    assert 'error' in json_data


def assert_rate(rate, target_rate):
    assert rate > target_rate, \
        'rate (%s) below %s execs per second' % (rate, target_rate)


def test_marshall_perform():
    request_id = 1
    now = datetime.datetime.utcnow()
    d1 = 1
    d2 = 2.2
    method_name = 'doit'
    # without date ------------------------------------------------
    # marshall ---
    marshall_params = (request_id, method_name, [d1, d2])
    (response, delta, rate) = _timeit(
        jsonrpc.marshall_request, marshall_params,
        iterations=10000
    )
    # about 135000 on i5
    assert_rate(rate, 70000)

    # unmarshall ---

    # about 135000 on i5
    request = response
    (response, delta, rate) = _timeit(
        jsonrpc.unmarshall_request, [request],
        iterations=10000
    )
    # about 120000 on i5
    assert_rate(rate, 70000)

    # with date ---------------------------------------------------
    marshall_params = (request_id, method_name, [d1, d2, now])
    (response, delta, rate) = _timeit(
        jsonrpc.marshall_request, marshall_params,
        iterations=10000
    )
    # about 85000 on i5
    assert_rate(rate, 60000)

    # unmarshall ---

    # about 135000 on i5
    request = response
    (response, delta, rate) = _timeit(
        jsonrpc.unmarshall_request, [request],
        iterations=10000
    )
    # about 50000 on i5
    assert_rate(rate, 20000)


def test_request_handler_perform():
    # logging debug can make this fail
    json_logger = logging.getLogger('scatterbytes.jsonrpc')
    json_logger.setLevel(logging.INFO)
    dt = datetime.datetime.now()
    json_data = jsonrpc.marshall_request(1, 'echo', [dt])
    raw_request_data = make_http_message(
        url='/JSON-RPC', body=json_data,
    )
    request = RequestMock(raw_request_data)
    server = ServerMock()
    address = '127.0.0.1:98765'

    f = jsonrpc.RPCRequestHandler
    dispatcher = jsonrpc.RPCDispatcher()
    dispatcher.register_instance(RPCFunctions())
    server.dispatcher = dispatcher
    (response, delta, rate) = _timeit(f, [request, address, server])
    # about 5500 on i5
    print rate
    assert_rate(rate, 5000)


# mock objects for testing handler

def test_rpc_server():
    host = '127.0.0.1'
    port = 15234
    dispatcher = jsonrpc.RPCDispatcher()
    dispatcher.register_instance(RPCFunctions())
    server = jsonrpc.RPCServer((host, port), dispatcher)
    t1 = threading.Thread(target=server.serve_forever)
    t1.start()
    print t1
    time.sleep(1)
    try:
        proxy = jsonrpc.RPCServerProxy('http://%s:%s/JSON-RPC' % (host, port))
        assert proxy.echo('hello world') == 'hello world'
    finally:
        print 'terminating'
        server.shutdown()
        print 'shutdown - joining'
        t1.join()
        server.server_close()


class RequestMock(object):

    def __init__(self, data):
        self.data = data
        self.client_cert_info = {}

    def makefile(self, mode, bufsize):
        if mode == 'wb':
            f = StringIO()
        else:
            f = StringIO(self.data)
        return f

    def shutdown(self, a):
        pass


class ServerMock(object):
    pass


class RPCFunctions(object):

    def echo(self, msg):
        return msg
    echo.published = True


class NormalRPCTestCase(unittest.TestCase):

    def setUp(self):
        self.json_data = jsonrpc.marshall_request(1, 'echo', ['hello world'])
        self.extra_headers = {
            'x-sb_auth_ts': datetime.datetime.utcnow().isoformat()
        }
        self.raw_request_data = make_http_message(
            url='/JSON-RPC', body=self.json_data,
        )
        self.request = RequestMock(self.raw_request_data)
        self.server = ServerMock()
        self.address = '127.0.0.1:98765'

    def test_request_handler_get_501(self):
        raw_request_data = make_http_message()
        request = RequestMock(raw_request_data)
        handler = jsonrpc.RPCRequestHandler(
            request, self.address, self.server
        )
        self.assert_(
            handler.wfile.buflist[0].startswith('HTTP/1.0 501')
        )

    def test_request_handler_post(self):
        print self.raw_request_data
        rpc_functions = RPCFunctions()
        dispatcher = jsonrpc.RPCDispatcher()
        dispatcher.register_instance(rpc_functions)
        self.server.dispatcher = dispatcher
        handler = jsonrpc.RPCRequestHandler(
            self.request, self.address, self.server
        )
        print handler.wfile.buflist[-1]
        print jsonrpc.unmarshall_response(handler.wfile.buflist[-1])
        (response, error, request_id) = \
            jsonrpc.unmarshall_response(handler.wfile.buflist[-1])
        self.assertEqual(response, 'hello world')

    def tearDown(self):
        pass
