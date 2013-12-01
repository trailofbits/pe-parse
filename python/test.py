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
sections = p.get_sections()
print "Sections: (%i)" % len(sections)
for sect in sections:
    print "[+] %s" % sect.name
    print "\tBase: %s" % hex(sect.base)
    print "\tLength: %s" % sect.length
    print "\tVirtual address: %s" % hex(sect.virtaddr)
    print "\tVirtual size: %i" % sect.virtsize
    print "\tNumber of Relocations: %i" % sect.numrelocs
    print "\tNumber of Line Numbers: %i" % sect.numlinenums
    print "\tCharacteristics: %s" % hex(sect.characteristics)
imports = p.get_imports()
print "Imports: (%i)" % len(imports)
for imp in imports:
    print "[+] Symbol: %s (%s %s)" % (imp.sym, imp.name, hex(imp.addr))
exports = p.get_exports()
print "Exports: (%i)" % len(exports)
for exp in exports:
    print "[+] Module: %s (%s %s)" % (exp.mod, exp.func, hex(exp.addr))
