import os
import re
import base64
import hashlib
from formencode import Invalid
from formencode import validators

# Thanks to Gavin Andresen's DJango BitCoin address validator, which this is
# baed on.


class BTCAddressField(validators.FancyValidator):

    messages = {'invalid': 'Invalid Bitcoin address.'}

    def validate_python(self, value, state):
        value = value.strip()
        if re.match(r"[a-zA-Z1-9]{27,35}$", value) is None:
            raise Invalid(self.message('invalid', state), value, state)
        version = get_bcaddress_version(value)
        if version is None:
            raise Invalid(self.message('invalid', state), value, state)
        return value


__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)


def b58encode(v):
    """ encode v, which is a string of bytes, to base58.
    """

    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += (256 ** i) * ord(c)
    result = ''
    while long_value >= __b58base:
        (div, mod) = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c != '\0':
            break
        nPad += 1

    return (__b58chars[0] * nPad) + result


def b58decode(v, length):
    """ decode v into a string of len bytes
    """
    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base ** i)

    result = ''
    while long_value >= 256:
        (div, mod) = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    nPad = 0
    for c in v:
        if c != __b58chars[0]:
            break
        nPad += 1

    result = chr(0) * nPad + result
    if length is not None and len(result) != length:
        return None

    return result


def get_bcaddress_version(strAddress):
    """

    Returns None if strAddress is invalid.  Otherwise returns integer version
    of address.

    """
    addr = b58decode(strAddress, 25)
    if addr is None:
        return None
    version = addr[0]
    checksum = addr[-4:]
    vh160 = addr[:-4]  # Version plus hash160 is what is checksummed
    h3 = hashlib.sha256(hashlib.sha256(vh160).digest()).digest()
    if h3[0:4] == checksum:
        return ord(version)
    return None


class BTCPaymentThreshold(validators.Int):
    """validate satoshi threshold for which payments are made to a storage node

    It is expressed in satoshi (10^-8 BTC) as an integer.

    """

    min = 10 ** 5
    max = 10 ** 9


class SecurePassword(validators.FancyValidator):

    min = 7
    non_letter = 1
    letter_regex = re.compile(r'[a-zA-Z]')

    messages = {
        'too_few': 'Your password must be longer than %(min)i '
        'characters long',
        'non_letter': 'You must include at least %(non_letter)i '
        'non letter in your password',
    }

    def validate_python(self, value, state):
        if len(value) < self.min:
            raise Invalid(
                self.message("too_few", state, min=self.min), value, state
            )
        non_letters = self.letter_regex.sub('', value)
        if len(non_letters) < self.non_letter:
            raise Invalid(
                self.message("non_letter", state, non_letter=self.non_letter),
                value, state
            )
        return True

    @classmethod
    def generate_random_value(self):
        attempts = 0
        while attempts < 100:
            try:
                data = base64.b32encode(os.urandom(10))
                password = SecurePassword.to_python(data)
                break
            except Invalid:
                continue
        return password


Email = validators.Email
