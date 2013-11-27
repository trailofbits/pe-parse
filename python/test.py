#!/usr/bin/env python

import sys
import pepy
from pprint import pprint

p = pepy.parse(sys.argv[1])
ep = p.get_entry_point()
byts = p.get_bytes(ep, 8)
print "Bytes at 0x%x: %s" % (ep, byts)
for sect in p.get_sections():
    pprint(sect)
