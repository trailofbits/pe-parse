#!/usr/bin/env python

import sys
import time
import pepy

p = pepy.parse(sys.argv[1])
ep = p.get_entry_point()
byts = p.get_bytes(ep, 8)
print "Magic: %s" % hex(p.magic)
print "Signature: %s" % hex(p.signature)
print "Machine: %s" % hex(p.machine)
print "Number of sections: %s" % p.numberofsections
print "Number of symbols: %s" % p.numberofsymbols
print "Characteristics: %s" % hex(p.characteristics)
print "Timedatestamp: %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.timedatestamp))
print "Major linker version: %s" % hex(p.majorlinkerver)
print "Minor linker version: %s" % hex(p.minorlinkerver)
print "Size of code: %s" % hex(p.codesize)
print "Size of initialized data: %s" % hex(p.initdatasize)
print "Size of uninitialized data: %s" % hex(p.uninitdatasize)
print "Address of entry point: %s" % hex(p.entrypointaddr)
print "Base address of code: %s" % hex(p.baseofcode)
print "Base address of data: %s" % hex(p.baseofdata)
print "Image base address: %s" % hex(p.imagebase)
print "Section alignment: %s" % hex(p.sectionalignement)
print "File alignment: %s" % hex(p.filealingment)
print "Major OS version: %s" % hex(p.majorosver)
print "Minor OS version: %s" % hex(p.minorosver)
print "Win32 version: %s" % hex(p.win32ver)
print "Size of image: %s" % hex(p.imagesize)
print "Size of headers: %s" % hex(p.headersize)
print "Checksum: %s" % hex(p.checksum)
print "Subsystem: %s" % hex(p.subsystem)
print "DLL characteristics: %s" % hex(p.dllcharacteristics)
print "Size of stack reserve: %s" % hex(p.stackreservesize)
print "Size of stack commit: %s" % hex(p.stackcommitsize)
print "Size of heap reserve: %s" % hex(p.heapreservesize)
print "Size of heap commit: %s" % hex(p.heapcommitsize)
print "Loader flags: %s" % hex(p.loaderflags)
print "Number of RVA and sizes: %s" % hex(p.rvasandsize)
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
