pepy
====
pepy (pronounced p-pie) is a python binding to the pe-parse parser.

Building
========
If you can build pe-parse and have a working python environment (headers and
libraries) you can build pepy.

1. Build pepy:
  * python setup.py build
2. Install pepy:
  * python setup.py install

Using
=====
Parsed object
-------------
There are a number of objects involved in pepy. The main one is the **parsed**
object. This object is returned by the *parse* method.

```
import pepy
p = pepy.parse("/path/to/exe")
```

The **parsed** object has a number of methods:

* get_entry_point: Return the entry point address
* get_bytes: Return the first N bytes at a given address
* get_sections: Return a list of section objects
* get_imports: Return a list of import objects.
* get_exports: Return a list of export objects.
* get_relocations: Return a list of relocation objects

The **parsed** object has a number of attributes:

* signature
* machine
* numberofsections
* timedatestamp
* numberofsymbols
* characteristics
* magic
* majorlinkerver
* minorlinkerver
* codesize
* initdatasize
* uninitdatasize
* entrypointaddr
* baseofcode
* baseofdata
* imagebase
* sectionalignement
* filealingment
* majorosver
* minorosver
* win32ver
* imagesize
* headersize
* checksum
* subsystem
* dllcharacteristics
* stackreservesize
* stackcommitsize
* heapreservesize
* heapcommitsize
* loaderflags
* rvasandsize

Example:
```
import time
import pepy

p = pepy.parse("/path/to/exe")
print "Timedatestamp: %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.timedatestamp))
ep = p.get_entry_point()
print "Entry point: 0x%x" % ep
```

The *get_sections*, *get_imports*, *get_exports* and *get_relocations* methods
each return a list of objects. The type of object depends upon the method called.
*get_sections* returns a list of **section** objects, *get_imports* returns a
list of **import** objects, etc.


Section Object
--------------
The **section** object has the following attributes:

* base
* length
* virtaddr
* virtsize
* numrelocs
* numlinenums
* characteristics

Import Object
-------------
The **import** object has the following attributes:

* sym
* name
* addr

Export Object
-------------
The **export** object has the following attributes:

* mod
* func
* addr

Relocation Object
-----------------
The **relocation** object has the following attributes:

* type
* addr

Authors
=======
pe-parse was designed and implemented by Andrew Ruef (andrew@trailofbits.com)
pepy was written by Wesley Shields (wxs@atarininja.org)
