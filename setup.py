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

import os
import platform
import sys

from setuptools import Extension, setup

here = os.path.dirname(__file__)
pepy = os.path.join(here, "pepy")

with open(os.path.join(here, "VERSION")) as f:
    VERSION = f.read().strip()

SOURCE_FILES = [
    os.path.join(pepy, "pepy.cpp"),
    os.path.join(here, "pe-parser-library", "src", "parse.cpp"),
    os.path.join(here, "pe-parser-library", "src", "buffer.cpp"),
]

INCLUDE_DIRS = []
LIBRARY_DIRS = []
LIBRARIES = []

if platform.system() == "Windows":
    SOURCE_FILES.append(
        os.path.join(here, "pe-parser-library", "src", "unicode_winapi.cpp")
    )
    INCLUDE_DIRS += [
        os.path.abspath(os.path.join(os.path.dirname(sys.executable), "include")),
        os.path.join(here, "pe-parser-library", "include"),
        "C:\\usr\\include",
    ]
    LIBRARY_DIRS += [
        os.path.abspath(os.path.join(os.path.dirname(sys.executable), "libs")),
        "C:\\usr\\lib",
    ]
    COMPILE_ARGS = ["/EHsc"]
else:
    SOURCE_FILES.append(
        os.path.join(here, "pe-parser-library", "src", "unicode_libicu.cpp")
    )
    INCLUDE_DIRS += [
        "/usr/local/include",
        "/opt/local/include",
        "/usr/include",
        os.path.join(here, "pe-parser-library", "include"),
    ]
    LIBRARY_DIRS += ["/usr/lib", "/usr/local/lib"]
    LIBRARIES += ["icuuc"]
    COMPILE_ARGS = ["-std=c++17"]

    # Add Homebrew ICU paths on macOS if ICU_ROOT is set
    if platform.system() == "Darwin":
        icu_root = os.environ.get("ICU_ROOT")
        if icu_root:
            INCLUDE_DIRS.insert(0, os.path.join(icu_root, "include"))
            LIBRARY_DIRS.insert(0, os.path.join(icu_root, "lib"))

extension_mod = Extension(
    "pepy",
    define_macros=[("PEPARSE_VERSION", f'"{VERSION}"')],
    sources=SOURCE_FILES,
    extra_compile_args=COMPILE_ARGS,
    language="c++",
    include_dirs=INCLUDE_DIRS,
    library_dirs=LIBRARY_DIRS,
    libraries=LIBRARIES,
)

# All metadata now comes from pyproject.toml
setup(ext_modules=[extension_mod])
