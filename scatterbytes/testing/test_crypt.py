import datetime
from scatterbytes import crypt
import M2Crypto.RSA
import M2Crypto.EVP

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

if __name__ == '__main__':
    test_sig_key()
