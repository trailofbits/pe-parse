#!/usr/bin/env python

import sys
import time
import pepy
import binascii

from hashlib import md5

try:
    p = pepy.parse(sys.argv[1])
except pepy.error as e:
    print e
    sys.exit(1)

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
try:
    print "Base address of data: %s" % hex(p.baseofdata)
except:
    # Not available on PE32+, ignore it.
    pass
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
ep = p.get_entry_point()
byts = p.get_bytes(ep, 8)
print "Bytes at %s: %s" % (hex(ep), ' '.join(['0x' + binascii.hexlify(b) for b in str(byts)]))
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
    if sect.length:
        print "\tFirst 10 bytes: 0x%s" % binascii.hexlify(sect.data[:10])
    print "\tMD5: %s" % md5(sect.data).hexdigest()
imports = p.get_imports()
print "Imports: (%i)" % len(imports)
for imp in imports:
    print "[+] Symbol: %s (%s %s)" % (imp.sym, imp.name, hex(imp.addr))
exports = p.get_exports()
print "Exports: (%i)" % len(exports)
for exp in exports:
    print "[+] Module: %s (%s %s)" % (exp.mod, exp.func, hex(exp.addr))
relocations = p.get_relocations()
print "Relocations: (%i)" % len(relocations)
for reloc in relocations:
    print "[+] Type: %s (%s)" % (reloc.type, hex(reloc.addr))
resources = p.get_resources()
print "Resources: (%i)" % len(resources)
for resource in resources:
    print "[+] MD5: (%i) %s" % (len(resource.data), md5(resource.data).hexdigest())
    if resource.type_str:
        print "\tType string: %s" % resource.type_str
    else:
        print "\tType: %s (%s)" % (hex(resource.type), resource.type_as_str())
    if resource.name_str:
        print "\tName string: %s" % resource.name_str
    else:
        print "\tName: %s" % hex(resource.name)
    if resource.lang_str:
        print "\tLang string: %s" % resource.lang_str
    else:
        print "\tLang: %s" % hex(resource.lang)
    print "\tCodepage: %s" % hex(resource.codepage)
    print "\tRVA: %s" % hex(resource.RVA)
    print "\tSize: %s" % hex(resource.size)
