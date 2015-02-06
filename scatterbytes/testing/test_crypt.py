import datetime
import unittest
import M2Crypto.RSA
import M2Crypto.EVP
from .. import crypt
from .. import errors


def test_sig_key():
    rsa_key = M2Crypto.RSA.gen_key(1024, 65537, lambda x: None)
    pkey = M2Crypto.EVP.PKey()
    pkey.assign_rsa(rsa_key)
    now = datetime.datetime.utcnow()
    messages = [
        ['hello', ],
        ['hello', now],
        ['hello', now, 1],
        ['hello', now, 1, 1.23345889],
        ['hello', now, 1, 1.23345889, ['hello', now, 1, 1.23345889]],
        dict(message='hello'),
        dict(message='hello', dt=now, number=1, float=3.1415926),
        dict(message='hello', dt=now, number=1, float=3.1415926,
             mapping=dict(message='hello', dt=now, number=1,
                          float=3.1415926)),
        dict(message='hello', dt=now, number=1, float=3.1415926,
             mapping=dict(message='hello', dt=now, number=1, float=3.1415926),
             things=['hello', now, 1, 1.23345889, ['hello', now, 1, 1.23345889]]
        ),

    ]
    for msg in messages:
        sigkey = crypt.SigKey(pkey)
        sigkey.sign(msg)
        sigkey.verify(msg)

class RSAKeyTestCase(unittest.TestCase):

    def setUp(self):
        self.key = crypt.RSAKey.generate_key()

    def test_key_ok(self):
        self.key.as_pem() == self.key._pem_string
        assert self.key._rsa_key.check_key()

    def test_as_pem(self):
        priv = self.key.as_pem()
        self.assert_(priv.startswith('-----BEGIN RSA PRIVATE KEY'))

    def test_sign_verify(self):
        data = 'testdata'
        sig = self.key.sign(data)
        self.assert_(self.key.verify(data, sig))

    def test_sign_verify_fail(self):
        sig = self.key.sign('abcd')
        self.assertRaises(errors.SignatureError, self.key.verify, 'abc', sig)

    def tearDown(self):
        del self.key


class PublicRSAKeyTestCase(unittest.TestCase):

    def setUp(self):
        self.priv_key = crypt.RSAKey.generate_key()
        pub_pem = self.priv_key.as_pem_pub()
        self.key = crypt.PublicRSAKey(pem_string=pub_pem)

    def test_key_ok(self):
        self.key.as_pem() == self.key._pem_string
        assert self.key._rsa_key.check_key()

    def test_as_pem(self):
        priv = self.key.as_pem()
        self.assert_(priv.startswith('-----BEGIN PUBLIC KEY'))

    def test_verify(self):
        pass

    def tearDown(self):
        del self.key
        del self.priv_key