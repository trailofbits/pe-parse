#!/usr/bin/env python

import sys
import time
import pepy

p = pepy.parse(sys.argv[1])
ep = p.get_entry_point()
byts = p.get_bytes(ep, 8)
print "Signature: %s" % hex(p.signature)
print "Machine: %s" % hex(p.machine)
print "Number of sections: %s" % p.numberofsections
print "Number of symbols: %s" % p.numberofsymbols
print "Characteristics: %s" % hex(p.characteristics)
print "Timedatestamp: %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.timedatestamp))
print "Bytes at 0x%x: %s" % (ep, byts)
print "Sections:"
for sect in p.get_sections():
    print "[+] %s" % sect.name
    print "\tBase: %s" % hex(sect.base)
    print "\tLength: %s" % sect.base
    print "\tVirtual address: %s" % hex(sect.base)
    print "\tVirtual size: %s" % sect.base
    print "\tNumber of Relocations: %s" % sect.base
    print "\tNumber of Line Numbers: %i" % sect.base
    print "\tCharacteristics: %s" % hex(sect.base)
