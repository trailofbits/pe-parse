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
* get_imports: Return a list of import objects
* get_exports: Return a list of export objects
* get_relocations: Return a list of relocation objects
* get_resources: Return a list of resource objects

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

The *get_sections*, *get_imports*, *get_exports*, *get_relocations* and
*get_resources* methods each return a list of objects. The type of object
depends upon the method called. *get_sections* returns a list of **section**
objects, *get_imports* returns a list of **import** objects, etc.

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
* data

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

Resource Object
---------------
The **resource** object has the following attributes:

* type_str
* name_str
* lang_str
* type
* name
* lang
* codepage
* RVA
* size
* data

The **resource** object has the following methods:

* type_as_str

Resources are stored in a directory structure. The first three levels of the
are called **type**, **name** and **lang**. Each of these levels can have
either a pre-defined value or a custom string. The pre-defined values are
stored in the *type*, *name* and *lang* attributes. If a custom string is
found it will be stored in the *type_str*, *name_str* and *lang_str*
attributes. The *type_as_str* method can be used to convert a pre-defined
type value to a string representation.

The following code shows how to iterate through resources:

```
import pepy

from hashlib import md5

p = pepy.parse(sys.argv[1])
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
```

Note that some binaries (particularly packed) may have corrupt resource entries.
In these cases you may find that len(resource.data) is 0 but resource.size is
greater than 0. The *size* attribute is the size of the data as declared by the
resource data entry.

Authors
=======
pe-parse was designed and implemented by Andrew Ruef (andrew@trailofbits.com)
pepy was written by Wesley Shields (wxs@atarininja.org)
