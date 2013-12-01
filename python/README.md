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

* signature: PE Signature
* machine: Machine
* numberofsections: Number of sections
* timedatestamp: Timedate stamp
* numberofsymbols: Number of symbols
* characteristics: Characteristics
* magic: Magic
* majorlinkerver: Major linker version
* minorlinkerver: Minor linker version
* codesize: Size of code
* initdatasize: Size of initialized data
* uninitdatasize: Size of uninitialized data
* entrypointaddr: Address of entry point
* baseofcode: Base address of code
* baseofdata: Base address of data
* imagebase: Image base address
* sectionalignement: Section alignment
* filealingment: File alignment
* majorosver: Major OS version
* minorosver: Minor OS version
* win32ver: Win32 version
* imagesize: Size of image
* headersize: Size of headers
* checksum: Checksum
* subsystem: Subsystem
* dllcharacteristics: DLL characteristics
* stackreservesize: Size of stack reserve
* stackcommitsize: Size of stack commit
* heapreservesize: Size of heap reserve
* heapcommitsize: Size of heap commit
* loaderflags: Loader flags
* rvasandsize: Number of RVA and sizes

Authors
=======
pe-parse was designed and implemented by Andrew Ruef (andrew@trailofbits.com)
pepy was written by Wesley Shields (wxs@atarininja.org)
