
Python DRBG: quility randomness!
================================

python-drbg is a Python 2.7 and 3.3+ compatible module that generates
strong random bytes, it implements NIST SP 800-90A.


Quickstart
----------

The easiest way to get started is to simply call :func:`drbg.generate`::
    
    >>> import drbg
    >>> drbg.generate(4)
    b'\x00(s\xa9'

This will automaticlly instantiate a global random number generator and
return the desired number of bytes (or an implementation specific number of
no arguments are given.)

A slightly more involved example involves selecting a specific mechanism such
as ``sha224hmac``::

    >>> import drbg
    >>> d = drbg.new('sha224hmac')
    >>> d.generate(5)
    b'\xd2e\x94+\x13'

See below for a complete list of :ref:`table-mechs`.


Overview
--------

Python DRBG offers the following features:
    
    * Easy and familiar interface.
    * Supports CTR (depends on Pycrypto), Hash and HMAC DRBG mechanisms.
    * Validated against NIST test vectors.
    * No Duel_EC_DRBG, which is slow and biased. This mechanism has also
      under suspicions of containing a backdoor.


.. _table-mechs:

Supported Mechanisms
~~~~~~~~~~~~~~~~~~~~

The following table shows all supported mechanisms and algorithms and
some of their properties. For more information refer to NIST SP 800-90A and
NIST SP 800-57.

+---------------------------+---------------------+--------------------------+
| name                      | mechanism           | security strength        | 
+===========================+=====================+============+=============+
| ``sha``, ``sha1``,        | Hash_DRBG           | ``digest_size / 2``      |
| ``sha224``, ``sha256``,   |                     |                          |
| ``sha512`` [1]_           |                     |                          |
+---------------------------+---------------------+--------------------------+
| ``sha``, ``sha1``,        | HMAC_DRBG           | ``digest_size / 2``      |
| ``sha224``, ``sha256``,   |                     |                          |
| ``sha512``. [1]_          |                     |                          |
+---------------------------+---------------------+--------------------------+
| ``aes128``, ``aes192``,   | CTR_DRBG            | ``128, 192, 256`` for    |
| ``aes256``, ``tdea`` [2]_ |                     | AES and ``168`` for TDEA |
+---------------------------+---------------------+--------------------------+

.. [1] Depends on the hash algorithms available in Pythons builtin ``hashlib`` module.
.. [2] Depends on the availability of Pycrypto.

The ``name`` parameter can be used as first argument to :func:`drbg.new` to
create a specific DRBG::

    >>> new('sha256hmac')
    >>> new('aes256')

Algorithm availability depends on the system and the availability of the Pycrypto
module. The availability of a specific algorithm can be queried by inspecting
the following two attributes:

.. autodata:: drbg.DIGESTS
    :annotation: = [...]

.. autodata:: drbg.CIPHERS
    :annotation: = [...]


API Reference
-------------

High Level
~~~~~~~~~~

To instantiate e new DRBG the :func:`drbg.new` function should be used.

.. autofunction:: drbg.new

The :func:`drbg.new` function returns an instance of :class:`drbg.RandomByteGenerator`, which
facilitates auto-reseed and offers a iterator interface.


.. autoclass:: drbg.RandomByteGenerator
    :members: generate

The :class:`drbg.RandomByteGenerator` also offers an iterator interface that yield an infinate
sequence of random bytes::

    >>> from itertools import islice
    >>> import drbg
    >>> bytes(islice(drbg.new(), 5))
    b'\xf3\xbc\x1d\xa1\xa3'


Low Level
~~~~~~~~~
Each DRBG mechanism is implemented in a separate class, which all derive
from the same :class:`drbg.DRBG` baseclass.

.. autoclass:: drbg.DRBG
    :members: init, generate, reseed


.. autoclass:: drbg.CTRDRBG
    :members:

.. autoclass:: drbg.HashDRBG
    :members:

.. autoclass:: drbg.HMACDRBG
    :members:
