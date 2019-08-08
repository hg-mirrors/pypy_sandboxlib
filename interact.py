#! /usr/bin/env python

"""Interacts with a subprocess translated with --sandbox.

Usage:
    interact.py <executable> <args...>
    interact.py --check <executable>
"""

import sys
import sandboxlib.main

if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] == '--help':
        print >> sys.stderr, __doc__
        sys.exit(2)
    sys.exit(sandboxlib.main.main(sys.argv[1:]))
