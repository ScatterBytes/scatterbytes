"""cryptography and hashing

"""

import os
import zlib
import types
import logging
import hashlib
import time
import datetime
import M2Crypto
import M2Crypto.EVP
from M2Crypto import SSL
from M2Crypto import X509
from M2Crypto.EVP import pbkdf2
from .errors import CertificateError, CRLError
from . import util
from .util import b64encode, b64decode, b32encode

logger = logging.getLogger(__name__)

# Seed the OpenSSL RNG
M2Crypto.Rand.rand_seed(os.urandom(1024))


def calc_file_crc32(f, contains_checksum=False):
    # number of bytes to read at one time
    read_size = 4096
    is_file = isinstance(f, file)
    if is_file:
        fl = f
        fl.seek(0)
    else:
        fl = open(f, 'rb')
    file_size = os.fstat(fl.fileno()).st_size
    crc32 = zlib.crc32
    cksum = crc32('') & 0xffffffff
    loc = fl.tell()
    while loc < file_size:
        if contains_checksum and loc + read_size > file_size - 4:
            cksum = crc32(
                fl.read(file_size - loc - 4),
                cksum
            ) & 0xffffffff
            break
        cksum = crc32(fl.read(read_size), cksum) & 0xffffffff
        loc = fl.tell()
    if not is_file:
        fl.close()
    return cksum


def calc_hash(data, salt=None, constructor=hashlib.sha1):
    s = constructor()
    if salt:
        s.update(salt)
    s.update(data)
    if salt:
        s.update(salt)
    hash = s.digest()
    if salt:
        hash = salt + hash
    return b64encode(hash)


def calc_file_hash(f, salt=None, constructor=hashlib.sha1,
                   return_type='base64'):
    """Calculate a hash for a file.

    f may be either a file like object or a file path.

    return type may be base64, base32, hex, or int

    """
    # number of bytes to read at one time
    assert return_type in ('base64', 'base32', 'hex')
    if salt:
        assert return_type == 'base64'
    read_size = 4096
    is_file = isinstance(f, file)
    if is_file:
        fl = f
        fl.seek(0)
    else:
        fl = open(f, 'rb')
    s = constructor()
    # A salt is used to prevent identification of files. For example, if one
    # uploaded the latest Ubuntu CD image, it could not be identified using
    # the hash because the salted hash would not likely match an existing hash
    # on the same file.
    if salt:
        s.update(salt)
    size = os.fstat(fl.fileno()).st_size
    # If this is a very small file, it's plausible that the contents could be
    # determined by brute force.  To prevent this, make it computationally
    # prohibitive.  Note that this only matters for the hash created for the
    # original file.
    if salt and size < 32:
        contents = fl.read()
        for i in xrange(1000):
            s.update(contents)
            s.update(salt)
            s.update(s.digest())
    while fl.tell() < size:
        s.update(fl.read(read_size))
        if salt:
            s.update(salt)
    if not is_file:
        fl.close()
    if return_type == 'hex':
        return s.hexdigest()
    elif return_type == 'base32':
        return b32encode(s.digest())
    hash = s.digest()
    if salt:
        hash = salt + hash
    return b64encode(hash)


# TLS keys and certificates

def stretch_passphrase(passphrase, salt=None, iterations=10000, length=32,
                       output_format='binary'):
    """Stretch a password using pbkdf2

    """

    if salt is None:
        salt = os.urandom(8)
    output = pbkdf2(passphrase, salt, iterations, length)
    if output_format != 'binary':
        output = util.b64encode(output)
    return output


class AESKey(object):

    def __init__(self, binary_key, binary_salt=None):
        self.binary_key = binary_key
        self.binary_salt = binary_salt
        if binary_salt:
            self.base64_salt = b64encode(binary_salt)
        else:
            self.base64_salt = None
        self.base64_key = b64encode(binary_key)

    def __str__(self):
        return self.base64_key

    def __len__(self):
        return len(self.base64_key)

    @classmethod
    def create_pbkdf2(cls, passphrase, salt='', iterations=10000, keylen=32):
        """Create an encryption key for AES using pbkdf2

        """

        if not salt:
            # 64 bit salt
            salt = os.urandom(8)
        binary_key = stretch_passphrase(passphrase, salt, iterations, keylen)
        return cls(binary_key, salt)


class Certificate(object):
    """wrapper for M2Crypto X509"""

    def __init__(self, filepath=None, certificate=None, pem_string=None):
        self._subject_text = None
        self._filepath = filepath
        self._pem_string = pem_string
        assert certificate or filepath or pem_string
        if filepath:
            self.cert = X509.load_cert(filepath)
        elif certificate:
            self.cert = certificate
        else:
            self.cert = X509.load_cert_string(pem_string)

    def as_pem(self):
        if self._pem_string:
            return self._pem_string
        elif self._filepath:
            return open(self._filepath).read()
        else:
            logger.warning("can't provide full PEM")
            return self.cert.as_pem()

    @property
    def serial_number(self):
        return self.cert.get_serial_number()

    @property
    def subject(self):
        return self.cert.get_subject()

    def get_subject_part(self, subject_part):
        if self._subject_text is None:
            self._subject_text = self.subject.as_text()
        subject_text = self._subject_text
        for part in subject_text.split(','):
            part = part.strip()
            if part.startswith(subject_part):
                return unicode(part.split('=')[1])

    def check_expire(self):
        # dates are UTC anyway so remove TZ
        before = self.cert.get_not_before().get_datetime().replace(tzinfo=None)
        after = self.cert.get_not_after().get_datetime().replace(tzinfo=None)
        print before, after
        now = datetime.datetime.utcnow()
        if now > after or now < before:
            emsg = "invalid cert with dates before: %s and after: %s"
            emsg = emsg % (before, after)
            raise CertificateError(emsg)

    @property
    def O(self):
        return self.get_subject_part('O')

    @property
    def OU(self):
        return self.get_subject_part('OU')

    @property
    def CN(self):
        return self.get_subject_part('CN')

    @property
    def public_key(self):
        return self.cert.get_pubkey()

    @property
    def info(self):
        return {
            'CN': self.CN,
            'O': self.O,
            'OU': self.OU,
            'serial_number': self.serial_number
        }

    def verify(self, pkey):
        """verify the certificate's signature

        """
        if not self.cert.verify(pkey):
            emsg = 'certificate %s failed validation' % self.subject
            raise CertificateError(emsg)

    def __getattr__(self, attname):
        return getattr(self.cert, attname)


class CRL(object):
    """wrapper for M2Crypto.X509.CRL

    adds ability to read details and check signature

    """

    def __init__(self, crl_path):
        self._crl_path = crl_path
        self._crl = X509.load_crl(crl_path)
        self.serial_numbers = []
        for line in self._crl.as_text().split('\n'):
            line = line.strip()
            if line.startswith('Last Update'):
                self.last_update = self._read_date(line)
            elif line.startswith('Next Update'):
                self.next_update = self._read_date(line)
            elif line.startswith("Serial Number:"):
                self.serial_numbers.append(line.split()[2])

    def _read_date(self, line):
        dt_str = line[12:].strip()
        fmt = "%b %d %H:%M:%S %Y %Z"
        return datetime.datetime.strptime(dt_str, fmt)

    def verify(self, sig, cert):
        """verify CRL with pkey

        sig
            external signature to work around M2Crypto not verifying CRL sig

        cert
            M2Crypto.X509.X509 instance - typically the root CA cert


        """
        assert sig
        pkey = cert.get_pubkey()
        pkey.verify_init()
        pkey.verify_update(open(self._crl_path, 'rb').read())
        if not pkey.verify_final(sig):
            raise CRLError('CRL signature verification failed.')


class CSR(object):
    """wrapper for M2Crypto CSR"""

    def __init__(self, csr):
        if isinstance(csr, basestring):
            csr = X509.load_request(csr)
        self._csr = csr

    @property
    def subject(self):
        return self._csr.get_subject()

    def get_subject_part(self, subject_part):
        for part in self.subject.as_text().split(','):
            part = part.strip()
            if part.startswith(subject_part):
                return part.split('=')[1]

    @property
    def O(self):
        return self.get_subject_part('O')

    @property
    def OU(self):
        return self.get_subject_part('OU')

    @property
    def CN(self):
        return self.get_subject_part('CN')

    @property
    def public_key(self):
        return self._csr.get_pubkey()


class SigKey(object):
    """key to sign messages and/or check signatures

    """

    def __init__(self, pkey):
        """

        pkey
          M2Crypto.EVP.PKey instance or PEM string

        """
        if isinstance(pkey, basestring):
            pkey = load_pkey(basestring)
        self.pkey = pkey

    def _prepare_message(self, message):
        """Prepare arguments for signing."""
        if isinstance(message, basestring):
            return message
        elif isinstance(message, types.NoneType):
            return ''
        elif isinstance(message, (int, long)):
            return str(message)
        elif isinstance(message, float):
            # if 6 places is not desired, it should be preformatted.
            return '%f' % message
        elif isinstance(message, (list, tuple)):
            prepared_arg = []
            for item in message:
                prepared_arg.append(self._prepare_message(item))
            return ''.join(prepared_arg)
        elif isinstance(message, dict):
            prepared_arg = []
            keys = message.keys()
            keys.sort()
            for key in keys:
                assert isinstance(key, basestring), 'keys should be strings'
                value = message[key]
                prepared_arg.append(
                    '%s%s' % (key, self._prepare_message(value)))
            return ''.join(prepared_arg)
        elif isinstance(message, datetime.datetime):
            # use the xmlrpc speced iso8601 format
            return message.strftime('%Y%m%dT%H%M%S')
        else:
            emsg = '%s of type %s not supported' % \
                (repr(message), type(message))
            raise StandardError(emsg)

    def sign(self, message):
        # insert timestamp first
        ts = datetime.datetime.utcnow()
        if isinstance(message, list):
            message.insert(0, ts)
        elif isinstance(message, dict):
            message['signature_time'] = ts
        else:
            raise ValueError('invalid arguments')
        msg = self._prepare_message(message)
        hash = hashlib.sha1(msg).digest()
        key = self.pkey
        key.sign_init()
        key.sign_update(hash)
        s = key.sign_final()
        sig = b64encode(s)
        ##sig = b64encode(key.sign_final())
        if isinstance(message, list):
            message.insert(0, sig)
        else:
            message['signature'] = sig

    def verify(self, message):
        assert isinstance(message, (list, dict, tuple))
        if isinstance(message, (list, tuple)):
            sig = message[0]
            msg = self._prepare_message(message[1:])
        else:
            msg = message.copy()
            sig = msg['signature']
            del msg['signature']
            msg = self._prepare_message(msg)
        hash = hashlib.sha1(msg).digest()
        sig = b64decode(sig)
        key = self.pkey
        key.verify_init()
        key.verify_update(hash)
        key.verify_final(sig)
        ##raise AuthenticationError


def make_context(ca_cert_path, cert_path, key_path, mode='client'):
    logger.debug('making context')
    logger.debug('ca_cert_path: %s' % ca_cert_path)
    logger.debug('cert_path: %s' % cert_path)
    logger.debug('key_path: %s' % key_path)
    logger.debug('mode: %s' % mode)
    ctx = SSL.Context('tlsv1')
    if mode != 'init':
        ctx.load_cert_chain(cert_path, key_path)
    ctx.load_verify_locations(ca_cert_path)
    if mode == 'init':
        ctx.set_verify(SSL.verify_peer, 2)
    else:
        ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 2)
    ctx.set_session_id_ctx('ScatterBytes')
    if mode != 'init':
        ctx.load_client_ca(ca_cert_path)
    #if util.LOG_LEVEL == logging.DEBUG:
    #    ctx.set_info_callback()
    #ctx.set_info_callback()
    return ctx


def prepare_ssl_output_dir(output_path):
    if output_path:
        output_dir = os.path.dirname(output_path)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, 0700)


def create_pkey(key_size=2048, output_path=None):
    """Create RSA key pair.

    """
    pkey = M2Crypto.EVP.PKey()
    rsa = M2Crypto.RSA.gen_key(key_size, 65537, lambda x: None)
    pkey.assign_rsa(rsa)
    if output_path:
        prepare_ssl_output_dir(output_path)
        pkey.save_key(output_path, None)
        os.chmod(output_path, 0600)
    return pkey


def load_pkey(key_path):
    """load a public key - with private key if available

    """
    return M2Crypto.EVP.load_key(key_path)


def create_csr(pkey, CN, O="ScatterBytes Network", output_path=None):
    """Create and return a M2Crypto.X509.Request

    """
    req = M2Crypto.X509.Request()
    assert req.set_pubkey(pkey)
    subject = req.get_subject()
    subject.CN = CN
    subject.O = O
    req.sign(pkey, 'sha1')
    assert req.verify(pkey)
    if output_path:
        prepare_ssl_output_dir(output_path)
        req.save(output_path)
    del pkey
    return req


def create_certificate(csr, serial_number, days_valid, ca_pkey,
                       ca_cert=None, is_ca=False, output_path=None):
    """Create a new X509 Certificate

    For a self signed cert, ca_cert is None.

    The cert chain will only be added when output_path is specified.

    """
    # for self signed, check that csr key matches public key
    # must be an easier way
    self_signed = ca_cert is None and \
        ca_pkey.as_der() == csr.get_pubkey().as_der()
    if self_signed:
        logger.debug('creating self signed certificate')
        assert is_ca, 'self signed cert must be a CA'
    cert = M2Crypto.X509.X509()
    cert.set_version(2)
    cert.set_serial_number(serial_number)
    cert.set_subject(csr.get_subject())
    if self_signed:
        cert.set_issuer(csr.get_subject())
    else:
        cert.set_issuer(ca_cert.get_subject())
    assert cert.set_pubkey(csr.get_pubkey())
    # set time
    t = long(time.time())
    now = M2Crypto.ASN1.ASN1_UTCTIME()
    now.set_time(t)
    future = M2Crypto.ASN1.ASN1_UTCTIME()
    future.set_time(t + 60 * 60 * 24 * days_valid)
    cert.set_not_before(now)
    cert.set_not_after(future)
    # CA
    if is_ca:
        extension = M2Crypto.X509.new_extension(
            'basicConstraints', 'CA:TRUE')
    else:
        extension = M2Crypto.X509.new_extension(
            'basicConstraints', 'CA:FALSE')
    cert.add_ext(extension)
    cert.sign(ca_pkey, 'sha1')
    prepare_ssl_output_dir(output_path)
    # If an intermediate CA is used, concantenate the CA cert.
    if not is_ca and output_path:
        cert.save_pem(output_path)
        open(output_path, 'ab').write(ca_cert.as_pem())
    elif is_ca and output_path:
        cert.save_pem(output_path)
    if ca_cert:
        assert cert.verify(ca_cert.get_pubkey())
    return cert


def load_certificate(cert_path=None, wrap=False):
    cert = X509.load_cert(cert_path)
    if wrap:
        cert = Certificate(certificate=cert)
    return cert
