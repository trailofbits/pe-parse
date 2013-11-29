#!/usr/bin/env python

import sys
import time
import pepy

p = pepy.parse(sys.argv[1])
ep = p.get_entry_point()
byts = p.get_bytes(ep, 8)
print "Signature: %s" % hex(p.signature)
print "Machine: %s" % hex(p.machine)
print "Timedatestamp: %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.timedatestamp))
print "Bytes at 0x%x: %s" % (ep, byts)
print "Sections:"
for sect in p.get_sections():
    print(sect)
