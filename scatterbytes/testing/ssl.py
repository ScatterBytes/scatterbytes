import os
import shutil
import zipfile
import datetime
import M2Crypto
from .. import crypt
from . import util as testutil


SERIAL_NUMBER = 10001
GEN_ALL_CALLED = False


def get_ssl_dir():
    if testutil.CACHE_DIR:
        ssl_dir = os.path.join(testutil.CACHE_DIR, 'ssl')
    else:
        assert testutil.TEST_DIR
        ssl_dir = os.path.join(testutil.TEST_DIR, 'ssl')
    if not os.path.exists(ssl_dir):
        os.makedirs(ssl_dir)
    return ssl_dir


def get_ssl_owner_dir(owner_name):
    ssl_dir = get_ssl_dir()
    output_path = os.path.join(ssl_dir, owner_name)
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    return output_path


def get_key_path(owner_name):
    owner_dir = get_ssl_owner_dir(owner_name)
    key_path = os.path.join(owner_dir, 'key.pem')
    if not os.path.exists(key_path):
        create_key(owner_name)
    return key_path


def get_key(owner_name):
    key_path = get_key_path(owner_name)
    return crypt.load_pkey(key_path)


def get_sig_key(owner_name):
    k = get_key(owner_name)
    return crypt.SigKey(k)


def get_cert_path(owner_name):
    return os.path.join(get_ssl_owner_dir(owner_name), 'cert.pem')


def get_cert(owner_name):
    return crypt.load_certificate(get_cert_path(owner_name))


def create_key(owner_name):
    # check for a cached key first
    owner_dir = get_ssl_owner_dir(owner_name)
    key_path = os.path.join(owner_dir, 'key.pem')
    if not os.path.exists(key_path):
        pkey = crypt.create_pkey()
        pkey.save_key(key_path, None)
    else:
        pkey = crypt.load_pkey(key_path)
    return pkey


def create_cert(owner_name, CN, O, serial_number, expire_months,
                ca_name='ca_1', is_ca=False):
    global SERIAL_NUMBER
    if serial_number is None:
        serial_number = SERIAL_NUMBER
        SERIAL_NUMBER += 1
    owner_dir = get_ssl_owner_dir(owner_name)
    cert_path = os.path.join(owner_dir, 'cert.pem')
    if not os.path.exists(cert_path):
        owner_key = get_key(owner_name)
        csr = crypt.create_csr(owner_key, CN, O)
        ca_key = get_key(ca_name)
        ca_cert = None
        if owner_name != ca_name:
            ca_cert = get_cert(ca_name)
        cert = crypt.create_certificate(
            csr, serial_number, expire_months * 30, ca_key, ca_cert, is_ca,
            cert_path
        )
    else:
        cert = crypt.load_certificate(cert_path)
    return cert


def create_cert_from_csr(csr_path, ca_name='ca_1', owner_name=None):
    csr = crypt.CSR(csr_path)
    if owner_name is None:
        owner_name = csr.CN
    O = csr.O
    CN = csr.CN
    serial_number = None
    expire_months = 9
    create_cert(owner_name, CN, O, serial_number, expire_months, ca_name)
    owner_dir = get_ssl_owner_dir(owner_name)
    # should be here
    cert_path = os.path.join(owner_dir, 'cert.pem')
    return cert_path


def _print_ca(ca_path):
    import subprocess
    cmd = ['openssl', 'x509', '-noout', '-text', '-in', ca_path]
    subprocess.call(cmd)


def gen_ssl_root_ca():
    name = 'ca_root'
    create_key(name)
    create_cert(
        name, 'ScatterBytes Root CA', 'ScatterBytes Network', 0,
        25 * 12, 'ca_root', is_ca=True
    )


def gen_ssl_ca_1():
    name = 'ca_1'
    create_key(name)
    create_cert(
        name, 'ScatterBytes Intermediate CA', 'ScatterBytes Network',
        1, 24, 'ca_root', is_ca=True
    )


def gen_ssl_ca_2():
    name = 'ca_2'
    create_key(name)
    create_cert(
        name, 'ScatterBytes Intermediate CA', 'ScatterBytes Network',
        2, 48, 'ca_root', is_ca=True
    )


def gen_ssl_control_node():
    name = 'control_node'
    create_key(name)
    create_cert(
        name, 'Control Node', 'ScatterBytes Network', 3, 24, 'ca_root'
    )


def gen_ssl_software_signer():
    name = 'software_signer'
    create_key(name)
    create_cert(
        name, 'ScatterBytes Software Signer', 'ScatterBytes Network',
        4, 24, 'ca_root'
    )


def gen_ssl_relay_command_signer():
    name = 'relay_command_signer'
    create_key(name)
    create_cert(
        name, 'ScatterBytes Relay Command Signer', 'ScatterBytes Network',
        5, 24, 'ca_root'
    )


def gen_ssl_node(name):
    create_key(name)
    create_cert(name, name, 'ScatterBytes Network', None, 8, 'ca_1')


def prepare_node_ssl_dir(node_id, node_type):
    """copy key and certs required by a node

    This is usually performed by the node as a function of the UserNode class,
    but I don't want to excercise UserNode for every test.

    """

    ssl_dir = get_ssl_dir()
    ssl_tgt_dir = os.path.join(
        testutil.TEST_DIR, '%s_nodes' % node_type, node_id, 'ssl'
    )

    # this will create certs if they do not exist
    gen_ssl_node(node_id)
    ssl_src_dir = get_ssl_owner_dir(node_id)
    # copy root cert
    shutil.copy(
        os.path.join(ssl_dir, 'ca_root', 'cert.pem'),
        os.path.join(ssl_tgt_dir, 'ca_root_cert.pem')
    )
    # software signer
    shutil.copy(
        os.path.join(ssl_dir, 'software_signer', 'cert.pem'),
        os.path.join(ssl_tgt_dir, 'software_signer_cert.pem')
    )
    # relay command signer
    shutil.copy(
        os.path.join(ssl_dir, 'relay_command_signer', 'cert.pem'),
        os.path.join(ssl_tgt_dir, 'relay_command_signer_cert.pem')
    )
    if node_type == 'storage':
        # node cert
        shutil.copy(
            os.path.join(ssl_src_dir, 'cert.pem'),
            os.path.join(ssl_tgt_dir, 'storage_node_cert.pem')
        )
        # node key
        shutil.copy(
            os.path.join(ssl_src_dir, 'key.pem'),
            os.path.join(ssl_tgt_dir, 'storage_node_key.pem')
        )
    else:
        # node cert
        shutil.copy(
            os.path.join(ssl_src_dir, 'cert.pem'),
            os.path.join(ssl_tgt_dir, 'client_node_cert.pem')
        )
        # node key
        shutil.copy(
            os.path.join(ssl_src_dir, 'key.pem'),
            os.path.join(ssl_tgt_dir, 'client_node_key.pem')
        )


def gen_crl(serial_numbers=None):
    # need pyopenssl to run this
    import OpenSSL
    if serial_numbers is None:
        serial_numbers = [3, 4]
    serial_numbers = map(str, serial_numbers)
    ssl_dir = get_ssl_dir()
    cert_path = os.path.join(ssl_dir, 'ca_root', 'cert.pem')
    key_path = os.path.join(ssl_dir, 'ca_root', 'key.pem')

    def null_callback(self, *args):
        pass
    passphrase = null_callback
    days = 90
    output_path = os.path.join(ssl_dir, 'ca_root_crl.pem')
    crl = OpenSSL.crypto.CRL()
    now = datetime.datetime.utcnow()
    now_str = now.strftime('%Y%m%d%H%M%SZ')
    for serial_number in serial_numbers:
        revoked = OpenSSL.crypto.Revoked()
        revoked.set_serial(serial_number)
        revoked.set_rev_date(now_str)
    PEM = OpenSSL.crypto.FILETYPE_PEM
    cert = OpenSSL.crypto.load_certificate(PEM, open(cert_path, 'rb').read())
    pkey = OpenSSL.crypto.load_privatekey(
        PEM, open(key_path, 'rb').read(), passphrase
    )
    open(output_path, 'wb').write(crl.export(cert, pkey, days=days))
    # sig
    crl_path = output_path
    output_path = crl_path + '.sig'
    pkey = M2Crypto.EVP.load_key(key_path)
    pkey.sign_init()
    crl_data = open(crl_path, 'rb').read()
    pkey.sign_update(crl_data)
    sig = pkey.sign_final()
    open(output_path, 'wb').write(sig)


def collect_certs():
    # put certs and crl in a zip file
    ssl_dir = get_ssl_dir()
    output_path = os.path.join(ssl_dir, 'scatterbytes_certs.zip')
    zf = zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED)

    def add_cert(name):
        path = os.path.join(ssl_dir, name, 'cert.pem')
        file_name = '%s_cert.pem' % name
        print path, file_name
        zf.write(path, file_name)
    add_cert('control_node')
    add_cert('software_signer')
    add_cert('relay_command_signer')
    add_cert('ca_1')
    add_cert('ca_root')
    i = 2
    while True:
        name = 'ca_%s_cert.pem'
        if os.path.exists(os.path.join(ssl_dir, name)):
            add_cert(name)
            i += 1
        else:
            break
    # add the crl
    zf.write(os.path.join(ssl_dir, 'ca_root_crl.pem'), 'ca_root_crl.pem')
    zf.write(os.path.join(ssl_dir, 'ca_root_crl.pem.sig'),
             'ca_root_crl.pem.sig')


def gen_ssl_all():
    gen_ssl_root_ca()
    gen_ssl_ca_1()
    gen_ssl_ca_2()
    gen_ssl_control_node()
    gen_ssl_software_signer()
    gen_ssl_relay_command_signer()
    gen_crl()
    collect_certs()

if __name__ == '__main__':
    test_dir = testutil.create_tmp_directory()
    try:
        gen_ssl_all()
        gen_ssl_node('whodat')
    finally:
        testutil.remove_tmp_directory()
