"""functionality common to both client and storage nodes

UserNode

    base class for StorageNode and ClientNode

"""

import os
import time
import shutil
import zipfile
import logging
import threading
from .errors import SBError, CertificateRequestError, ConfigError
from . import crypt


logger = logging.getLogger(__name__)


class UserNode(object):

    """base class for ClientNode and StorageNode

    config
        configuration instance

    control_node_proxy
        proxy instance for the control node

    snode_proxy_creator
        function to create a storage node proxy

    cert
        TLS Certificate

    """

    node_O = 'ScatterBytes Network'

    def __init__(self, control_node_proxy, snode_proxy_creator, config=None):
        if config:
            self.config = config
        else:
            self.config = self.config_class.get_config()
        self.control_node_proxy = control_node_proxy
        self.snode_proxy_creator = snode_proxy_creator
        self.ssl_context_gen_lock = threading.Lock()
        self.loaded_certificates = False
        self.cert_cache = {}

    def _create_private_key(self):
        key_path = self.config.private_key_path
        crypt.create_pkey(output_path=key_path)

    def get_certificate(self, owner_name):
        ssl_dir = self.config.get('ssl_dir')
        return get_certificate(ssl_dir, owner_name, self.cert_cache)

    def load_certificates(self, retries=3, wait_time=10):
        """Get all server certificates from the control node.

        This includes:
            * software signer certificate
            * relay command signer certificate
            * root CA's CRL
            * signature for CRL (hack) - M2Crypto can't verify CRL

        retries
            number of times to retry for failed attempts

        wait_time
            seconds to wait between attempts

        """

        ssl_dir = self.config.get('ssl_dir')
        try:
            download_certificates(
                self.control_node_proxy, ssl_dir, retries, wait_time
            )
        except Exception as e:
            logger.error(e)
            raise
        self.loaded_certificates = True
        # make sure we have ours
        self.check_certificate()

    def check_certificate(self):
        """Check our certificate and get a new one if needed.

        """
        if not os.path.exists(self.config.cert_path):
            self.request_new_certificate()
            # need to reload the ssl context on control node proxy
            if hasattr(self.control_node_proxy, 'reload_ssl_context'):
                self.control_node_proxy.reload_ssl_context()

    def request_new_certificate(self):
        """Obtain an X509 certificate from the control node.

        If a valid certificate code is set in configuration, as is done during
        service initialization, a certificate is obtained from the control
        node.

        """

       # the private key should have already been generated.
        if not os.path.exists(self.config.private_key_path):
            raise SBError("must first generate private key")
        logger.info('requesting X509 certificate')
        # generate a CSR
        pkey = crypt.load_pkey(self.config.private_key_path)
        csr = crypt.create_csr(pkey, self.node_id, self.node_O)
        # csr is in X509.Request form - must convert to pem in memory
        csr_pem = csr.as_pem()
        # segfault was occuring - maybe from loading this twice? - once here
        # and once at the control node
        del csr
        # base64 encoded - will require no special treatment
        recert_code = self.config.get('recert_code')
        if not recert_code:
            raise SBError('recert_code not set in config')
        proxy = self.control_node_proxy
        response = proxy.create_certificate(self.node_id, recert_code, csr_pem)
        # cert will be in pem format and ready to save
        cert_pem = response['certificate']
        cert_path = self.config.cert_path
        open(cert_path, 'wb').write(cert_pem)
        logger.info('got certificate')

    def show_account(self):
        return self.control_node_proxy.get_account_info()

    def make_ssl_context(self):
        "generate an ssl context for this node"
        with self.ssl_context_gen_lock:
            ctx = self.config.make_ssl_context()
        return ctx

    @property
    def certificate(self):
        """certificate belonging to this instance"""
        return self.config.certificate

    @property
    def node_id(self):
        return self.config.get('node_id')

    @node_id.setter
    def node_id(self, value):
        self.config.set('node_id', value)
        self.config.save()


def get_certificate(ssl_dir, owner_name, cache=None):
    """get a certificate by name"""
    if cache is None:
        cache = {}
    cert = cache.get(owner_name, None)
    if not cert:
        cert_path = os.path.join(
            ssl_dir, "%s_cert.pem" % owner_name
        )
        cert = crypt.load_certificate(cert_path, wrap=True)
        cache[owner_name] = cert
    return cert


def download_certificates(
    control_node_proxy, ssl_dir, retries=0, wait_time=0
):
    """Get all server certificates from the control node.

    This includes:
        * software signer certificate
        * relay command signer certificate
        * root CA's CRL
        * signature for CRL (hack) - M2Crypto can't verify CRL

    retries
        number of times to retry for failed attempts

    wait_time
        seconds to wait between attempts

    """

    logger.info('fetching certificates')

    attempts = 0
    zip_path = None
    while attempts <= retries:
        logger.debug('attempt: %s of %s' % (attempts + 1, retries + 1))
        try:
            zip_path = control_node_proxy.get_certificates()
            break
        except Exception:
            logger.warning('cert download failed', exc_info=True)
            emsg = 'could not load certs - try again in %s seconds'
            logger.error(emsg % wait_time)
            time.sleep(wait_time)
        attempts += 1
    if not zip_path:
        raise CertificateRequestError('unable to retrieve certificates')

    # f should be a file path
    # data is in zip format
    logger.debug(zip_path)
    zf = zipfile.ZipFile(zip_path)
    assert not zf.testzip()
    logger.debug('got the zip file and it checks out.')
    crl_data = zf.read('ca_root_crl.pem')
    crl_data_sig = zf.read('ca_root_crl.pem.sig')
    # save to temporary path
    crl_path = os.path.join(ssl_dir, 'ca_root_crl.pem')
    crl_path_tmp = os.path.join(ssl_dir, 'ca_root_crl.pem.tmp')
    open(crl_path_tmp, 'wb').write(crl_data)
    # check the crl
    logger.debug('checking crl')
    ca_root_cert = get_certificate(ssl_dir, 'ca_root')
    crl = crypt.CRL(crl_path_tmp)
    crl.verify(crl_data_sig, ca_root_cert)
    logger.debug('verified crl.')
    # looks OK
    shutil.move(crl_path_tmp, crl_path)
    # get and check the certs now
    for cert_name in ('software_signer_cert.pem',
                      'relay_command_signer_cert.pem'):
        cert_data = zf.read(cert_name)
        path = os.path.join(ssl_dir, cert_name)
        path_tmp = os.path.join(ssl_dir, cert_name + '.tmp')
        open(path_tmp, 'wb').write(cert_data)
        cert = crypt.Certificate(path_tmp)
        cert.verify(ca_root_cert.get_pubkey())
        assert cert.serial_number not in crl.serial_numbers
        # Everything check out.
        shutil.move(path_tmp, path)
        logger.debug('saved cert %s' % cert_name)
    logger.info('certificate download and verification complete')
