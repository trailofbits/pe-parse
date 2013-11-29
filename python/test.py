#!/usr/bin/env python

import sys
import time
import pepy
import binascii

from pprint import pprint

p = pepy.parse(sys.argv[1])
ep = p.get_entry_point()
byts = p.get_bytes(ep, 8)
print "Timedatestamp: %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.timedatestamp))
print "Bytes at 0x%x: %s" % (ep, byts)
for sect in p.get_sections():
    pprint(sect)
