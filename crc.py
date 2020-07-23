#!/usr/bin/env python3
# vim: set fileencoding=utf-8 :

__appname__     = "crc"
__author__      = "@AUTHOR@"
__copyright__   = ""
__credits__     = ["@AUTHOR@"]  # Authors and bug reporters
__license__     = "GPL"
__version__     = "1.0"
__maintainers__ = "@AUTHOR@"
__email__       = "@EMAIL@"
__status__      = "Prototype"  # "Prototype", "Development" or "Production"
__module__      = ""


def crc(barray) -> int:
    """
    this is CRC-16-ANSI (0x8005)
      >>> hex(crc([0x07, 0x00, 0x8f, 0x13, 0x03]))
      '0x1ac9'

      >>> hex(crc([0x06, 0x00, 0xa7, 0x13]))
      '0x753b'
    """
    magic = [0, 52225, 55297, 5120, 61441, 15360, 10240, 58369, 40961, 27648, 30720, 46081, 20480, 39937, 34817, 17408]

    def nbytes(i, n):
        return i & ((1 << (n * 4)) - 1)

    def helper(i, b):
        i = nbytes(i >> 4, 3) ^ magic[nbytes(i, 1)]
        i ^= magic[nbytes(b, 1)]
        i = nbytes(i >> 4, 3) ^ magic[nbytes(i, 1)]
        i ^= magic[nbytes(b >> 4, 1)]
        return i

    acc = 0
    for b in barray:
        acc  = helper(acc, b)
    return acc


import doctest
doctest.testmod()
