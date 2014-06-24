import os
import time

import M2Crypto.threading
import hashlib
import logging
import threading
import unittest
from M2Crypto import m2, SSL

from . import ssl, util as testutil, node as node_util
from .. import util, errors
from ..client.chunk import split_file
from ..jsonrpc import gen_storage_node_proxy_creator, StorageNodeProxy
from ..storage.jsonrpc import create_storage_node, StorageNodeSSLServer
from .test_storagenode import gen_chunk_name, gen_transfer_name
from .test_storagenode import make_expiretime, ControlNodeMockup


logger = logging.getLogger(__name__)
testutil.setup_logging()

TEST_FILE_PATH = None
TEST_CHUNKS = None

LISTEN_ADDRESS = '127.0.0.1'


def setup():
    M2Crypto.threading.init()
    TEST_DIR = testutil.create_tmp_directory()
    global TEST_FILE_PATH
    TEST_FILE_PATH = testutil.create_temp_file(int(2 ** 22 * 1.5))
    output_dir = os.path.join(TEST_DIR, 'file_chunks')
    os.mkdir(output_dir)
    logger.debug('splitting file %s' % TEST_FILE_PATH)
    chunks = split_file(TEST_FILE_PATH, output_dir, compress=False)
    global TEST_CHUNKS
    TEST_CHUNKS = chunks
    logger.debug('done splitting file')
    # generate ssl keys and certs
    ssl.gen_ssl_all()


def make_control_node_context():
    ca_cert_path = ssl.get_cert_path('ca_root')
    key_path = ssl.get_key_path('control_node')
    cert_path = ssl.get_cert_path('control_node')
    ctx = SSL.Context('tlsv1')
    ctx.load_cert_chain(cert_path, key_path)
    ctx.load_verify_locations(ca_cert_path)
    ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 2)
    ctx.set_session_id_ctx('ScatterBytes')
    ctx.load_client_ca(ca_cert_path)
    ctx.set_session_cache_mode(m2.SSL_SESS_CACHE_SERVER)
    return ctx


class BaseMixIn(object):

    def _upload_chunk(self, chunk, transfer_name, chunk_name, snode_name=None):
        expire_time = make_expiretime(2)
        transfers = self.control_node_proxy.transfers
        self.transfers = transfers
        snode_serial_number = self.snode_config.cert_info['serial_number']
        transfers[transfer_name] = {
            'chunk': chunk,
            'chunk_name': chunk_name,
            # serial number
            'receiving_node_id': snode_serial_number,
            'chunk_name': chunk_name
        }
        self.transfer = transfers[transfer_name]
        self.transfer_name = transfer_name
        # sender serial, receiver serial, .., ..
        chunk_hash_salt = util.b64encode(os.urandom(4))
        chunk.salt = chunk_hash_salt
        sn_args = [1002, self.snode_config.cert_info['serial_number'],
                   expire_time, transfer_name, chunk_name, chunk_hash_salt]
        if snode_name is None:
            snode_name = self.snode_name
        snode_info = self.storage_nodes[snode_name]
        snode_port = snode_info['port']
        sn_proxy = self.make_sn_proxy(port=snode_port)
        self.control_node_proxy._sign_args(sn_args)
        # don't have to pass serial numbers
        del sn_args[2]
        del sn_args[2]
        f = open(chunk.file_path, 'rb')
        sn_args.append(f)
        response = sn_proxy.store_chunk(*sn_args)
        self.assertEqual(response, 'OK')

    def create_storage_node_server(self, startup_registration_updater=True):
        if not hasattr(self, 'storage_nodes'):
            self.storage_nodes = {}
            self.storage_node_ports = []
        node_names = sorted(self.storage_nodes.keys())
        if not node_names:
            node_name = 'SN000001'
            node_port = 40000
        else:
            last_name = node_names[-1]
            node_name = 'SN' + str(int(last_name[2:]) + 1).zfill(6)
            node_port = self.storage_node_ports[-1] + 1
        self.storage_node_ports.append(node_port)
        # generate a cert
        # ssl.gen_ssl_node(node_name)
        snode_config = node_util.prepare_node(node_name, 'storage', True)
        snode_config.set('listen_address', LISTEN_ADDRESS, section='network')
        snode_config.set('listen_port', node_port, section='network')
        proxy_creator = gen_storage_node_proxy_creator(snode_config)
        storage_node = create_storage_node(
            self.control_node_proxy,
            proxy_creator,
            snode_config
        )
        server = StorageNodeSSLServer(storage_node)
        if not startup_registration_updater:
            server.storage_node.startup_registration_updater = False
        server.storage_node.startup()
        t = threading.Thread(target=server.serve_forever)
        t.start()
        self.storage_nodes[node_name] = {
            'port': node_port,
            'server': server,
            'server_thread': t,
            'storage_node': storage_node
        }
        return node_name

    @property
    def storage_node(self):
        # default storage node
        return self.storage_nodes[self.snode_name]['storage_node']

    def make_sn_proxy(self, ssl_context=None, port=None):
        if ssl_context is None:
            ssl_context = self.client_ctx
        if port is None:
            port = self.snode_port
        sn_proxy = StorageNodeProxy(
            "https://%s:%s" % (LISTEN_ADDRESS, port), ssl_context
        )
        return sn_proxy

    def test_check_hash(self):
        chunk = TEST_CHUNKS[3]
        sn_proxy = self.make_sn_proxy(ssl_context=self.control_node_ctx)
        self._upload_chunk(chunk, gen_transfer_name(), gen_chunk_name())
        chunk_name = self.transfer['chunk_name']
        salt = os.urandom(4)
        hash = chunk.calc_hash(salt=salt)
        response = sn_proxy.check_hash(chunk_name, util.b64encode(salt))
        self.assertEqual(response['chunk_hash'], hash)


class SingleThreadedTestCase(unittest.TestCase, BaseMixIn):

    def setUp(self):
        client_node_name = 'EEFFGGFF'
        self.client_node_name = client_node_name
        # generate a cert
        ssl.gen_ssl_node(client_node_name)
        client_config = node_util.prepare_node(
            client_node_name, 'client', True
        )
        self.client_config = client_config
        control_node_proxy = ControlNodeMockup()
        self.control_node_proxy = control_node_proxy
        # create 1 storage node to begin with
        self.snode_name = self.create_storage_node_server(
            startup_registration_updater=False
        )
        snode_info = self.storage_nodes[self.snode_name]
        self.snode_port = snode_info['port']
        self.snode_config = snode_info['storage_node'].config
        # client_context
        self.client_ctx = client_config.make_ssl_context()
        # control node context
        self.control_node_ctx = make_control_node_context()

    def test_send_chunk(self):
        chunk = TEST_CHUNKS[0]
        transfer_name = gen_transfer_name()
        chunk_name = gen_chunk_name()
        self._upload_chunk(chunk, transfer_name, chunk_name)
        # create a nother server
        snode2_name = self.create_storage_node_server(
            startup_registration_updater=False
        )
        snode2_info = self.storage_nodes[snode2_name]
        snode2_port = snode2_info['port']
        snode2 = snode2_info['storage_node']
        # need the serial number to sign the request
        snode2_serial_number = snode2.certificate.serial_number
        # create argument list to sign
        from_serial = self.storage_node.certificate.serial_number
        to_serial = snode2_serial_number
        expire_time = make_expiretime(5)
        transfer_name = gen_transfer_name()
        auth_args = [from_serial, to_serial, expire_time, transfer_name,
                     chunk_name, chunk.salt]
        self.control_node_proxy._sign_args(auth_args)
        chunk_name = self.transfer['chunk_name']
        signature = auth_args[0]
        signature_ts = auth_args[1]
        # register a new transfer on the control node
        self.transfers[transfer_name] = {
            'chunk_name': chunk_name,
            'chunk': chunk,
            'receiving_node_id': to_serial,
        }
        # use the context of the control node
        sn_proxy = self.make_sn_proxy(self.control_node_ctx, self.snode_port)
        priority = 20
        uri = "https://%s:%s" % ('127.0.0.1', snode2_port)
        # test
        # sn_proxy2 = self.make_sn_proxy(self.control_node_ctx, snode2_port)
        # response = sn_proxy2.hello()
        # self.assertEqual(response, 'Hello Control Node!')
        # self._upload_chunk(chunk, transfer_name, chunk_name, snode2_name)
        response = sn_proxy.send_chunk(
            chunk_name, chunk.salt, uri, transfer_name, priority,
            signature, signature_ts, expire_time
        )
        self.assertEqual(response, 'OK')
        # Second storage node should have the chunk.
        # Give it time to make the transfer.
        time.sleep(1)
        try:
            chunk_new = snode2._get_chunk(chunk_name)
        except errors.ChunkNotFoundError:
            time.sleep(1)
            chunk_new = snode2._get_chunk(chunk_name)
        self.assertEqual(
            chunk.calc_hash(),
            chunk_new.calc_hash()
        )

    def test_store_chunk(self):
        chunk = TEST_CHUNKS[0]
        transfer_name = gen_transfer_name()
        chunk_name = gen_chunk_name()
        self._upload_chunk(chunk, transfer_name, chunk_name)
        # check what was sent to the server
        cn_proxy = self.control_node_proxy
        args = cn_proxy.confirm_transfer_args
        self.assertEqual(args[0], self.storage_node.certificate.serial_number)
        self.assertEqual(args[1], transfer_name)
        self.assertEqual(args[2], chunk.calc_hash(util.b64decode(chunk.salt)))
        new_path = self.storage_node.config.find_chunk_path(
            self.transfer['chunk_name'])
        self.assert_(os.path.exists(new_path))

    def test_retrieve_chunk(self):
        chunk = TEST_CHUNKS[3]
        file_size = os.stat(chunk.file_path).st_size
        expire_time = make_expiretime(30)
        self._upload_chunk(chunk, gen_transfer_name(), gen_chunk_name())
        chunk_name = self.transfer['chunk_name']
        expire_time = make_expiretime(5)
        # sender serial, receiver serial, .., ..
        auth_args = [1002, self.storage_node.certificate.serial_number,
                     expire_time, chunk_name]
        self.control_node_proxy._sign_args(auth_args)
        args = auth_args
        args.insert(6, 31)
        args.insert(6, 30)
        # remove serial
        args.pop(2)
        args.pop(2)
        sn_proxy = self.make_sn_proxy()
        # read the first byte
        f = open(chunk.file_path, 'rb')
        f.seek(30)
        byte = f.read(1)
        f.close()
        f = sn_proxy.retrieve_chunk(*args)
        self.assertEqual(f.read(), byte)
        # read the last byte
        f = open(chunk.file_path, 'rb')
        f.seek(file_size - 1)
        byte = f.read()
        f.close()
        args[-2] = file_size - 1
        args[-1] = file_size
        f = sn_proxy.retrieve_chunk(*args)
        self.assertEqual(f.read(), byte)
        # read the first byte
        f = open(chunk.file_path, 'rb')
        byte = f.read(1)
        f.close()
        args[-2] = 0
        args[-1] = 1
        f = sn_proxy.retrieve_chunk(*args)
        self.assertEqual(f.read(), byte)
        # read 2K
        f = open(chunk.file_path, 'rb')
        f.seek(500)
        bytes = f.read(2048)
        f.close()
        args[-2] = 500
        args[-1] = 500 + 2048
        f = sn_proxy.retrieve_chunk(*args)
        self.assertEqual(
            hashlib.sha1(f.read()).hexdigest(),
            hashlib.sha1(bytes).hexdigest()
        )
        f.close()
        # read entire file
        args[-2] = 0
        args[-1] = file_size
        f = sn_proxy.retrieve_chunk(*args)
        # calling read immiediately results in an Incomplete Read error
        data = f.read()
        self.assertEqual(
            hashlib.sha1(data).hexdigest(),
            hashlib.sha1(open(chunk.file_path, 'rb').read()).hexdigest()
        )
        f.close()

    def test_delete_chunk(self):
        chunk = TEST_CHUNKS[3]
        self._upload_chunk(chunk, gen_transfer_name(), gen_chunk_name())
        chunk_name = self.transfer['chunk_name']
        chunk_path = self.storage_node.config.find_chunk_path(chunk_name)
        self.assert_(os.path.exists(chunk_path))
        sn_proxy = self.make_sn_proxy(ssl_context=self.control_node_ctx)
        response = sn_proxy.delete_chunk(chunk_name)
        self.assert_('mbytes_available' in response)
        self.assert_(not os.path.exists(chunk_path))

    def tearDown(self):

        import time
        time.sleep(.1)
        for (node_name, node_info) in self.storage_nodes.items():
            logger.debug('shutting down %s' % node_name)
            server = node_info['server']
            t_shut = threading.Thread(target=server.shutdown)
            self.storage_nodes[node_name]['shutdown_thread'] = t_shut
            t_shut.start()
        for (node_name, node_info) in self.storage_nodes.items():
            logger.debug('joining %s shutdown thread' % node_name)
            node_info['shutdown_thread'].join()
            logger.debug('joining %s server thread' % node_name)
            node_info['server_thread'].join()
            del node_info['server']
        del self.storage_nodes


def teardown():
    testutil.remove_tmp_directory()
    M2Crypto.threading.cleanup()
