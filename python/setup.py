# Copyright (c) 2013, Wesley Shields <wxs@atarininja.org>. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from distutils.core import setup, Extension

INCLUDE_DIRS = ['/usr/local/include',
                '/opt/local/include',
                '/usr/include',
                '../parser-library']
LIBRARY_DIRS = ['/usr/lib',
                '/usr/local/lib']

extension_mod = Extension('pepy',
                          sources = ['pepy.cpp',
                                     '../parser-library/parse.cpp',
                                     '../parser-library/buffer.cpp'],
                          extra_compile_args = ["-g", "-O0"], # Debug only
                          include_dirs = INCLUDE_DIRS,
                          library_dirs = LIBRARY_DIRS)


setup (name = 'pepy',
       version = '0.1',
       description = 'python bindings for pe-parse',
       author = 'Wesley Shields',
       author_email = 'wxs@atarininja.org',
       license = 'BSD',
       long_description = 'Python bindings for pe-parse',
       ext_modules = [extension_mod])
