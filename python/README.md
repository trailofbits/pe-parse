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
There are a number of objects involved in pepy. The main one is the *parsed*
object. This object is returned by the *parse* method.

`
import pepy
p = pepy.parse("/path/to/exe")
`

The *parsed* object has a number of methods:

* get_entry_point: Return the entry point address
* get_bytes: Return the first N bytes at a given address
* get_sections: Return a list of section objects
* get_imports: Return a list of import objects.
* get_exports: Return a list of export objects.
* get_relocations: Return a list of relocation objects

Authors
=======
pe-parse was designed and implemented by Andrew Ruef (andrew@trailofbits.com)
pepy was written by Wesley Shields (wxs@atarininja.org)
