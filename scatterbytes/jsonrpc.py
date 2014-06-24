"""JSON-RPC functionality

"""
import datetime
import os
import re
import time
from datetime import datetime as DT

import decimal
import hashlib
import inspect
import json
import logging
from BaseHTTPServer import BaseHTTPRequestHandler
from json import JSONEncoder, JSONDecoder
from urlparse import urlparse

import errors
from . import util, https
from .util import FamilyThreadMixIn
from .util import datetime_from_string, datetime_to_string


logger = logging.getLogger(__name__)

PROTOCOL_VERSION = '0.8'


datetime_re = re.compile(
    r'(\d{4})-(\d{2})-(\d{2})(T(\d{2}):(\d{2}):(\d{2}).(\d+))?'
)

# Index SBError sublcasses to meet the JSONRPC standard.
# Must be an integer not predefined (-32768 to -32000)

sb_error_index = {}

INIT_REQUEST_ID = int(time.time() * 10 ** 6)


def gen_request_id():
    return int(time.time() * 10 ** 6) - INIT_REQUEST_ID


def create_sb_error_index(error_name):
    """base the integer index on the name"""
    return int(hashlib.sha1(error_name).hexdigest()[:8], 16)


def index_sb_errors():
    for name in dir(errors):
        o = getattr(errors, name)
        if inspect.isclass(o) and issubclass(o, errors.SBError):
            index = create_sb_error_index(o.__name__)
            sb_error_index[index] = o

index_sb_errors()


# Define Errors
# ----------------------------------------------------------------------------


class JSONRPCError(StandardError):
    json_code = 0
    json_message = 'an error occurred'
    json_data = ''

    def __str__(self):
        msgs = filter(None, [self.json_message, self.json_data, self.message])
        return ' - '.join(map(repr, msgs))


class ParseError(JSONRPCError):

    json_code = -32700
    json_message = 'Parse error'


class InvalidRequest(JSONRPCError):

    json_code = -32600
    json_message = 'Invalid Request'


class MethodNotFound(JSONRPCError):

    json_code = -32601
    json_message = 'Method not found'


class InvalidParams(JSONRPCError):

    json_code = -32602
    json_message = 'Invalid params'


class InternalError(JSONRPCError):

    json_code = -32603
    json_message = 'Internal error'


class ServerError(JSONRPCError):

    json_code = -32000
    json_message = 'Server error'


# JSON-RPC Encode/Decode and Marshalling
# ----------------------------------------------------------------------------


class SBJSONEncoder(json.JSONEncoder):

    DATE = datetime.date

    def default(self, obj):
        if isinstance(obj, DT):
            return {
                'data_type':  'datetime',
                'value': datetime_to_string(obj)
            }
        if isinstance(obj, self.DATE):
            return {
                'data_type':  'datetime',
                'value': datetime_to_string(obj)
            }
        if isinstance(obj, decimal.Decimal):
            return {
                'data_type':  'decimal',
                'value': str(obj)
            }
        elif isinstance(obj, JSONRPCError):
            return {
                'code': obj.json_code,
                'message': obj.json_message,
                'data': obj.json_data
            }
        else:
            return JSONEncoder.encode(self, obj)

# encoder to handle special types

encoder = SBJSONEncoder()


def decode_object(d):
    data_type = d.get('data_type', None)
    if data_type:
        if data_type == 'datetime':
            return datetime_from_string(d['value'])
    elif data_type == 'decimal':
        return decimal.Decimal(d['value'])
    return d

# decoder to handle special types

decoder = JSONDecoder(object_hook=decode_object)


def marshall_request(request_id, method_name, params):
    """create a jsonrpc request"""
    d = {
        'jsonrpc': '2.0',
        'method': method_name,
        'params': params,
        'protocol': PROTOCOL_VERSION,
        'id': request_id
    }
    return encoder.encode(d)


def unmarshall_request(m):
    """convert json to method, params, and request_id"""
    ##logger.debug('unmarshalling request %s' % str(m))
    d = decoder.decode(m)
    method_name = d['method']
    params = d['params']
    request_id = d['id']
    return (request_id, method_name, params)


def marshall_response(request_id, result=None, error=None):
    """create a jsonrpc response"""
    d = {
        'jsonrpc': '2.0',
        'id': request_id
    }
    if error:
        d['error'] = error
    else:
        d['result'] = result
    try:
        return encoder.encode(d)
    except:
        logger.debug('failed to marshall %s' % str(d))
        raise


def unmarshall_response(m):
    """convert json to method, params, and request_id"""
    d = decoder.decode(m)
    request_id = d['id']
    result = d.get('result')
    error = d.get('error')
    return (result, error, request_id)


def wrap_error(e):
    """Wrap an SBError in a JSON Error"""
    e_index = create_sb_error_index(e.__class__.__name__)
    if e_index in sb_error_index:
        # Create a JSONRPCError and assign code and message.
        new_e = JSONRPCError()
        new_e.json_code = e_index
        new_e.json_message = e.message
        return new_e
    return None


def unwrap_error(e):
    if e['code'] in sb_error_index:
        ue = sb_error_index[e['code']]
        raise ue(e['message'])
    else:
        raise errors.SBError(e['message'])


# JSON-RPC HTTP Services
# ----------------------------------------------------------------------------


class RPCDispatcher(object):

    def __init__(self, obj=None):
        self.funcs = {}
        if obj:
            self.register_instance(obj)

    def register_instance(self, instance):
        """register published methods for instance

        methods with "published" attribute will be registered.

        """
        for (member_name, member) in inspect.getmembers(instance):
            if inspect.ismethod(member) and \
                    getattr(member, 'published', False):
                self.register_function(member, member_name)

    def register_function(self, function, name=None):
        if name is None:
            name = function.__name__
        self.funcs[name] = function

    def _dispatch(self, method, params):
        """dispatch request and return results or an error"""
        func = self.funcs.get(method, None)
        if func is None:
            raise MethodNotFound()
        else:
            return self.funcs[method](*params)

    def marshalled_dispatch(self, data, client_cert_info=None):
        try:
            (request_id, method_name, params) = unmarshall_request(data)
            # generate response
            if client_cert_info:
                params = [client_cert_info, ] + list(params)
            # response should be a legit response or an RPCError
            response = self._dispatch(method_name, params)
            return marshall_response(
                request_id=request_id, result=response
            )
        except JSONRPCError as e:
            return marshall_response(request_id=request_id, error=e)
        except errors.SBError as e:
            json_error = wrap_error(e)
            return marshall_response(request_id=request_id, error=json_error)
        except Exception as e:
            # using exc_info in testing causes a delay
            logger.error(str(e), exc_info=True)
            return marshall_response(
                request_id=request_id, error=InternalError()
            )
            ##logger.error(str(Exception))
            # The default implementation calls sys.exc_info, but calling
            # sys.exc_info causes a delay in the response. I don't know why -
            # maybe something related to threading or M2Crypto or both.
            # May be related to nose.  It occures when capturing logging, but
            # not with --nologcapture


class RPCRequestHandler(BaseHTTPRequestHandler):
    """JSON-RPC Request Handler.

    """

    server_version = "ScatterBytes Server"

    # No need to use compression - let SSL handle it.

    def read_incoming_data(self):
        #logger.debug('reading data')
        if not self.path.startswith('/JSON-RPC'):
            self.report_404()
            return
        # RPC should never need to be more than 1MB
        max_size = 10 ** 6
        content_length = int(self.headers["content-length"])
        logger.debug('content length: %s' % content_length)
        # even if content length > max_size, need to read data from socket
        logger.debug('reading up to %s bytes' % max_size)
        data = self.rfile.read(min(content_length, max_size))
        if len(data) != content_length:
            logger.warning('data length does not match')
            self.report_400()
            return
        return data

    def do_POST(self):
        """Interpret and dispatch JSON-RPC

        """

        logger.debug('handling POST')
        if self.server.dispatcher is None:
            raise Exception('no dispatcher defined')
        try:
            data = self.read_incoming_data()
            if not data:
                return
            # try to dispatch
            logger.debug('dispatching')
            cert_info = getattr(self.request, 'client_cert_info', None)
            response = self.server.dispatcher.marshalled_dispatch(
                data, client_cert_info=cert_info
            )
            logger.debug('got response')
        except Exception as e:
            # bug in program
            # log it
            logger.error(e.message, exc_info=True)
            # send 500
            self.send_response(500)
            self.send_header("Content-length", "0")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.send_header("Content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    def log_message(self, format, *args):
        (host, port) = self.client_address[:2]
        address = '%s:%s' % (host, port)
        msg = "%s - - [%s] %s\n" % (
            address, self.log_date_time_string(), format % args
        )
        logger.log(19, msg)

    def report_404(self):
        logger.debug('sending 404')
        self.send_response(404)
        response = "No such page"
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


# JSON-RPC Proxy
# Much of this is taken from xmlrpclib.


class _Method:
    def __init__(self, send, name):
        self.__send = send
        self.__name = name

    def __getattr__(self, name):
        return _Method(self.__send, "%s.%s" % (self.__name, name))

    def __call__(self, *args):
        return self.__send(self.__name, args)


class RPCServerProxy(object):

    def __init__(self, url, ssl_context=None, source_address=('', 0)):
        self._url = url
        o = urlparse(url)
        scheme = o.scheme
        host = o.hostname
        port = o.port
        if not port:
            if scheme == 'https':
                port = 443
            else:
                port = 80
        url_path = o.path
        self._url = url
        if not url_path:
            url_path = '/JSON-RPC'
        self._url_path = url_path
        self._scheme = scheme
        self._port = port
        self._host = host
        self._source_address = source_address
        self._ssl_context = ssl_context

    def _make_connection(self):
        return https.create_connection(
            self._url.encode('latin1'), ssl_context=self._ssl_context,
            source_address=self._source_address
        )

    def __getattr__(self, name):
        # magic method dispatcher
        return _Method(self._request, name)

    def _request(self, method_name, parameters):
        logger.debug('requesting %s from control node' % method_name)
        request_id = gen_request_id()
        data = marshall_request(request_id, method_name, parameters)
        con = self._make_connection()
        try:
            con.connect()
            logger.debug('sending POST %s' % str(data))
            con.request(
                method='POST', url=self._url_path, body=data
            )
            response = con.getresponse()
            data = response.read()
            if response.status != 200:
                emsg = 'HTTP status not 200. '
                emsg = emsg + 'Response: %s, Data: %s' % (
                    response.status, data
                )
                logger.error(emsg)
                raise errors.HTTPError(emsg)
            assert response.status == 200, response.status
            (result, error, request_id_ret) = unmarshall_response(data)
            logger.debug('result: %s' % str(result))
            logger.debug('error: %s' % str(error))
            if error:
                # try to identify the error
                unwrap_error(error)
            else:
                return result
        except Exception as e:
            logger.debug('got error: %s' % str(e))
            raise
        finally:
            con.close()
            del con


class RPCServer(https.HTTPServer):
    """JSON-RPC Server.

    single-threaded JSON-RPC server

    """

    def __init__(self, (ip_address, port), dispatcher,
                 request_handler=RPCRequestHandler, log_requests=True):
        self.logRequests = log_requests
        self.dispatcher = dispatcher
        https.HTTPServer.__init__(self, (ip_address, port), request_handler)


class SSLRPCServer(https.HTTPSServer):
    """JSON-RPC Server.

    single-threaded SSL JSON-RPC server

    """

    def __init__(self, (ip_address, port), dispatcher, ssl_context,
                 request_handler=RPCRequestHandler, log_requests=True):
        self.logRequests = log_requests
        https.HTTPSServer.__init__(
            self, (ip_address, port), request_handler, ssl_context
        )
        self.dispatcher = dispatcher


class ThreadedRPCServer(https.ThreadedHTTPServer, FamilyThreadMixIn):
    """JSON-RPC Server.

    multi-threaded JSON-RPC server

    """

    def __init__(self, (ip_address, port), dispatcher,
                 request_handler=RPCRequestHandler, log_requests=True):
        self.set_parent()
        self.logRequests = log_requests
        self.dispatcher = dispatcher
        https.ThreadedHTTPServer.__init__(
            self, (ip_address, port), request_handler
        )


class ThreadedSSLRPCServer(https.ThreadedHTTPSServer, FamilyThreadMixIn):
    """JSON-RPC Server.

    multi-threaded SSL JSON-RPC server

    """

    def __init__(self, (ip_address, port), dispatcher, ssl_context,
                 request_handler=RPCRequestHandler, log_requests=True):

        self.set_parent()
        self.logRequests = log_requests
        https.ThreadedHTTPSServer.__init__(
            self, (ip_address, port), request_handler, ssl_context
        )
        self.dispatcher = dispatcher


class ControlNodeProxy(RPCServerProxy):
    """Proxy to the control node.

    configuration based on the client's settings

    """

    def __init__(self, config, source_address=('', 0)):
        address = config.get('control_node_address', section='network')
        port = config.get('control_node_port', section='network')
        url = "https://%s:%s" % (address, port)
        logger.debug('Created a control node proxy to %s' % url)
        ctx = config.make_ssl_context()
        self.config = config
        RPCServerProxy.__init__(self, url, ctx, source_address=source_address)

    def reload_ssl_context(self):
        self._ssl_context = self.config.make_ssl_context()

    def make_get_request(self, url):
        """Make a GET request using the exisiting SSL session.

        """

        o = urlparse(url)
        logger.debug('request: %s' % url)
        con = self._make_connection()
        con.request('GET', o.path)
        try:
            response = con.getresponse()
            data = response.read()
        finally:
            con.close()
        return data

    def get_certificates(self):
        address = self.config.get('control_node_address', section='network')
        port = self.config.get('control_node_port', section='network')
        url = "https://%s:%s/updates/scatterbytes_certs.zip" % (address, port)
        zipf_data = self.make_get_request(url)
        output_path = os.path.join(
            self.config.get('ssl_dir'), 'scatterbytes_certs.zip',
        )
        open(output_path, 'wb').write(zipf_data)
        return output_path


class StorageNodeProxy(RPCServerProxy):

    def __init__(self, url, ssl_context=None, source_address=('', 0)):
        RPCServerProxy.__init__(self, url, ssl_context, source_address)

    def store_chunk(self, sig, sig_ts, expire_time, transfer_name,
                    chunk_name, chunk_hash_salt, chunk_data):

        url_path = '/sbfile/%s' % chunk_name
        logger.debug('storing chunk at %s' % url_path)
        # figure out the content length
        if isinstance(chunk_data, file):
            content_length = os.fstat(chunk_data.fileno()).st_size
        else:
            content_length = len(chunk_data)
        headers = [
            ('x-sb-sig', sig),
            ('x-sb-sig-ts', util.datetime_to_string(sig_ts)),
            ('x-sb-transfer-name', transfer_name),
            ('x-sb-hash-salt', chunk_hash_salt),
            ('x-sb-expire-time', util.datetime_to_string(expire_time)),
            ('Content-Type', 'application/octet-stream'),
            ('Content-Length', content_length)
        ]
        # make connection
        con = self._make_connection()
        try:
            con.request(
                method='PUT', url=url_path, body=chunk_data, headers=headers
            )
            r = con.getresponse(buffering=True)
            response = r.read()
        finally:
            con.close()
            del con
        assert r.status == 201
        logger.debug('chunk stored, response is %s' % str(response))
        return response

    def retrieve_chunk(self, auth, auth_ts, expire_time, chunk_name,
                       byte_start=0, byte_end=0):
        url_path = '/sbfile/%s' % chunk_name
        logger.debug('request to %s' % url_path)
        headers = [
            ('x-sb-auth', auth),
            ('x-sb-action', 'RETRIEVE_CHUNK'),
            ('x-sb-auth-ts', util.datetime_to_string(auth_ts)),
            ('x-sb-expire-time', util.datetime_to_string(expire_time)),
        ]
        if byte_end > 0:
            # HTTP Spec uses inclusive ranges.
            headers.append(('bytes', '%s-%s' % (byte_start, byte_end - 1)))
        con = self._make_connection()
        con.request('GET', url_path, headers=headers)
        response = con.getresponse(buffering=True)
        con.close()
        del con
        return response


def gen_storage_node_proxy_creator(config):

    def create_storage_node_proxy(url):
        ssl_context = config.make_ssl_context()
        return StorageNodeProxy(url, ssl_context)

    return create_storage_node_proxy
