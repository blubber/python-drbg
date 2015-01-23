
import hashlib
import hmac
import math
import re
import os
import sys

from functools import reduce

try:
    import Crypto
except ImportError:
    WITH_CRYPTO = False

PY3 = sys.version_info.major == 3

DIGESTS = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512']

class Error (Exception): pass
class UnknownAlgorithm (Exception): pass
class ReseedRequired (Exception): pass


def bytes2long (b):
    if PY3:
        num = int.from_bytes(b, 'big')
    else:
        length = len(b) - 1
        num = sum(c * 256**(length - exp) for exp, c in enumerate(b))
        
    return num


def long2bytes (l):
    b = bytearray()

    while l > 0:
        b.append(l & 0xff)
        l >>= 8

    b.reverse()
    return bytes(b)


class DigestDRBG (object):

    max_entropy_length = 2**32
    max_personalization_string_length = 2**32
    max_additional_input_length = 2**32
    max_number_of_bits_per_request = 2**19
    reseed_interval = 2**32

    def __init__ (self, digest, entropy_input, nonce, personalization_string=None):
        if not digest in DIGESTS:
            raise ValueError('Unsupported digest {}'.format(digst))

        self.digest = digest

        if not isinstance(entropy_input, (bytes, bytearray)):
            raise TypeError('entropy_input: expected bytes or bytearray.')

        if not isinstance(nonce, (bytes, bytearray)):
            raise TypeError('nonce: expected bytes or bytearray.')

        if not personalization_string is None and \
                not isinstance(personalization_string, (bytes, bytearray)):
            raise TypeError('personalization_string: expected bytes or bytearray.')

        if not self.security_strength <= 8 * len(entropy_input) <= self.max_entropy_length:
            raise Error('Entropy length invalid.')

        if personalization_string and 8 * len(personalization_string) > self.max_personalization_string_length:
            raise Error('Personalization string too long')

        self.reseed_counter = 1

    @property
    def security_strength (self):
        return self.outlen // 2

    @property
    def outlen (self):
        h = getattr(hashlib, self.digest)
        return 8 * h().digest_size


class HashDRBG (DigestDRBG):

    def __init__ (self, digest, entropy_input, nonce, personalization_string=None):
        super(HashDRBG, self).__init__(digest, entropy_input, nonce, personalization_string)
        self.seedlen = 440

        self.df = self._create_hash_df(getattr(hashlib, digest))

        personalization_string = personalization_string or b''

        self.__V = self.df(entropy_input + nonce, self.seedlen)
        self.__C = self.df(b'\x00' + self.__V, self.seedlen)


    def reseed (self, entropy_input, additional_input=None):
        additional_input = additional_input or b''
        self.__V = self.df(b'\x01' + self.__V + entropy_input + additional_input, self.seedlen)
        self.__C = self.df(b'\x00' + self.__V, self.seedlen)
        self.reseed_counter = 1


    def generate (self, requested_length, additional_input=None):
        digest = getattr(hashlib, self.digest)

        def hashgen (req, V):
            m = math.ceil(req / self.outlen)
            data = V
            w = b''
            for i in range(m):
                w += digest(data).digest()
                data = long2bytes((bytes2long(data) + 1) % 2**self.seedlen)
            return w[:(req + 4) // 8]


        if not additional_input is None:
            w = digest(b'\x02' + self.__V + additional_input).digest()
            V = long2bytes((bytes2long(self.__V) + bytes2long(w)) % 2**self.seedlen)
        else:
            V = self.__V

        out = hashgen(requested_length, V)
        H = digest(b'\x03' + V).digest()
        V = long2bytes((bytes2long(V) + bytes2long(H) + bytes2long(self.__C) + self.reseed_counter) % 2**self.seedlen)
        self.__V = V
        return out        

    def _create_hash_df (self, primitive):

        def df (input_string, no_of_bits_to_return):
            output = b''
            iterations = math.ceil(no_of_bits_to_return / self.outlen)
            return_bit_count = bytearray([
                no_of_bits_to_return >> 24,
                (no_of_bits_to_return >> 16) & 0xff,
                (no_of_bits_to_return >> 8) & 0xff,
                no_of_bits_to_return & 0xff
            ])

            for counter in range(iterations):
                output += primitive(chr((counter + 1) % 255).encode('utf-8') +
                                    return_bit_count + input_string).digest()

            return output[:(no_of_bits_to_return + 4) // 8]

        return df



class HMACDRBG (DigestDRBG):

    def __init__ (self, digest, entropy_input, nonce, personalization_string=None):        
        super(HMACDRBG, self).__init__(digest, entropy_input, nonce, personalization_string)

        outlen = self.outlen // 8
        self.__key, self.__V = self.update(b'\0' * outlen, b'\x01' * outlen,
                                           entropy_input, nonce,
                                           personalization_string)


    def generate (self, requested_length, additional_input=None):
        requested_length = (requested_length + 4) // 8

        K, V = self.update(self.__key, self.__V, additional_input)
        out = b''

        while len(out) < requested_length:
            V = self._mac(K, V)
            out += V

        self.reseed_counter += 1
        return out[:requested_length]


    def update (self, K, V, *provided_input):
        K = self._mac(K, V, b'\x00', *provided_input)
        V = self._mac(K, V)

        if provided_input:
            K = self._mac(K, V, b'\x01', *provided_input)
            V = self._mac(K, V)

        return K, V


    def reseed (self, entropy_input, additional_input=None):
        self.__key, self.__V = self.update(self.__key, self.__V, entropy_input, additional_input)
        self.reseed_counter = 1


    def _mac (self, K, V, *Vs):
        value = V + b''.join(v for v in Vs if v is not None)
        mac = hmac.new(K, value, digestmod=self.digest)
        return mac.digest()


def new (name, personalization_string=None):
    entropy = os.urandom(128)
    nonce = os.urandom(128)
    drbg = None

    matches = re.match('(sha[0-9]{1,3})(hmac)?', name.lower())

    if matches:
        digest = matches.group(1)
        use_hmac = not matches.group(2) is None

        if digest not in DIGESTS:
            raise ValueError('Unsupported digest {}'.format(digest))

        if use_hmac:
            drbg = HMACDRBG(digest, entropy, nonce, personalization_string)

    return drbg



