/*
 * Copyright (c) 2013, Wesley Shields <wxs@atarininja.org>. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <Python.h>
#include <structmember.h>
#include "parse.h"

#define PEPY_VERSION "0.1"

static PyObject *pepy_error;

typedef struct {
	PyObject_HEAD
} pepy;

typedef struct {
	PyObject_HEAD
	uint32_t signature;
	uint32_t machine;
	uint32_t timedatestamp;
	parsed_pe *pe;
} pepy_parsed;

static PyObject *pepy_parsed_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	pepy_parsed *self;

	self = (pepy_parsed *) type->tp_alloc(type, 0);

	return (PyObject *) self;
}

static int pepy_parsed_init(pepy_parsed *self, PyObject *args, PyObject *kwds) {
	PyObject *py_str;
	char *pe_path = NULL;

	if (!PyArg_ParseTuple(args, "S:pepy_parse", &py_str)) {
		return -1;
	}

	pe_path = PyString_AsString(py_str);
	if (!pe_path)
		return -1;

	self->pe = ParsePEFromFile(pe_path);
	if (!self->pe) {
		return -2;
	}

	Py_DECREF(py_str);

	self->signature = self->pe->peHeader.nt.Signature;
	self->machine = self->pe->peHeader.nt.FileHeader.Machine;
	self->timedatestamp = self->pe->peHeader.nt.FileHeader.TimeDateStamp;
	return 0;
}

static void pepy_parsed_dealloc(pepy_parsed *self) {
	DestructParsedPE(self->pe);
	self->ob_type->tp_free((PyObject *) self);
}

static PyObject *pepy_parsed_get_entry_point(PyObject *self, PyObject *args) {
	VA entrypoint;
	PyObject *ret;

	if (!GetEntryPoint(((pepy_parsed *) self)->pe, entrypoint))
		Py_RETURN_NONE;

	ret = PyLong_FromLongLong(entrypoint);
	if (!ret) {
		PyErr_SetString(pepy_error, "Unable to create return object.");
		return NULL;
	}

	return ret;
}

static PyObject *pepy_parsed_get_bytes(PyObject *self, PyObject *args) {
	uint64_t start, idx;
	uint8_t b;
	Py_ssize_t len;
	PyObject *byte, *ret;

	if (!PyArg_ParseTuple(args, "KK:pepy_parsed_get_bytes", &start, &len))
		return NULL;

	/*
	 * XXX: I want this to be using PyByteArray_FromStringAndSize(),
	 * but, I'm not sure how to get what I need out of the parsed PE
	 * to make it work.
	 */
	ret = PyList_New(len);
	if (!ret) {
		PyErr_SetString(pepy_error, "Unable to create new list.");
		return NULL;
	}

	for (idx = 0; idx < len; idx++) {
		if (!ReadByteAtVA(((pepy_parsed *) self)->pe, start + idx, b))
			return ret;

		byte = PyInt_FromLong(b);
		PyList_SET_ITEM(ret, idx, byte);
	}

	return ret;
}

int section_callback(void *cbd, VA base, std::string &name, image_section_header s, bounded_buffer *data) {
	PyObject *vals;
	PyObject *list = (PyObject *) cbd;
	PyObject *sect = PyDict_New();
	Py_ssize_t i = 0;

	/* This order must match the order of the tuple (vals). */
	const char *keys[] = { "name", "base", "size", "virtaddr", "virtsize",
	                       "relocs", "linenums", "characteristics" };

	if (!sect)
		return 0;

	vals = Py_BuildValue("sKKIIHHI", name.c_str(), base, data->bufLen,
	                    s.VirtualAddress, s.Misc.VirtualSize,
	                    s.NumberOfRelocations, s.NumberOfLinenumbers,
	                    s.Characteristics);
	if (!vals)
		Py_DECREF(sect);

	for (i = 0; i <= 7; i++) {
		if (PyDict_SetItemString(sect, keys[i], PyTuple_GetItem(vals, i)) == -1) {
			Py_DECREF(vals);
			Py_DECREF(sect);
			return 0;
		}
	}

	if (PyList_Append(list, sect) == -1) {
		Py_DECREF(vals);
		Py_DECREF(sect);
	}

	return 0;
}

static PyObject *pepy_parsed_get_sections(PyObject *self, PyObject *args) {
	PyObject *ret = PyList_New(0);
	if (!ret) {
		PyErr_SetString(pepy_error, "Unable to create new list.");
		return NULL;
	}

	IterSec(((pepy_parsed *)self)->pe, section_callback, ret);

	return ret;
}

static PyMemberDef pepy_parsed_members[] = {
	{ (char *) "signature", T_UINT, offsetof(pepy_parsed, signature), READONLY,
	  (char *) "Signature" },
	{ (char *) "machine", T_UINT, offsetof(pepy_parsed, machine), READONLY,
	  (char *) "Machine" },
	{ (char *) "timedatestamp", T_UINT, offsetof(pepy_parsed, timedatestamp),
	  READONLY, (char *) "Timestamp" },
	{ NULL }
};

static PyMethodDef pepy_parsed_methods[] = {
	{ "get_entry_point", pepy_parsed_get_entry_point, METH_NOARGS,
	  "Return the entry point address." },
	{ "get_bytes", pepy_parsed_get_bytes, METH_VARARGS,
	  "Return the first N bytes at a given address." },
	{ "get_sections", pepy_parsed_get_sections, METH_NOARGS,
	  "Return a list of dictionaries describing the sections." },
	{ NULL }
};

static PyTypeObject pepy_parsed_type = {
	PyObject_HEAD_INIT(NULL)
	0,                                /* ob_size */
	"pepy.parsed",                    /* tp_name */
	sizeof(pepy_parsed),              /* tp_basicsize */
	0,                                /* tp_itemsize */
	(destructor) pepy_parsed_dealloc, /* tp_dealloc */
	0,                                /* tp_print */
	0,                                /* tp_getattr */
	0,                                /* tp_setattr */
	0,                                /* tp_compare */
	0,                                /* tp_repr */
	0,                                /* tp_as_number */
	0,                                /* tp_as_sequence */
	0,                                /* tp_as_mapping */
	0,                                /* tp_hash */
	0,                                /* tp_call */
	0,                                /* tp_str */
	0,                                /* tp_getattro */
	0,                                /* tp_setattro */
	0,                                /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,               /* tp_flags */
	"parsed object",                  /* tp_doc */
	0,                                /* tp_traverse */
	0,                                /* tp_clear */
	0,                                /* tp_richcompare */
	0,                                /* tp_weaklistoffset */
	0,                                /* tp_iter */
	0,                                /* tp_iternext */
	pepy_parsed_methods,              /* tp_methods */
	pepy_parsed_members,              /* tp_members */
	0,                                /* tp_getset */
	0,                                /* tp_base */
	0,                                /* tp_dict */
	0,                                /* tp_descr_get */
	0,                                /* tp_descr_set */
	0,                                /* tp_dictoffset */
	(initproc) pepy_parsed_init,      /* tp_init */
	0,                                /* tp_alloc */
	pepy_parsed_new,                  /* tp_new */
};

static PyObject *pepy_parse(PyObject *self, PyObject *args) {
	PyObject *parsed;
	int ret;

	parsed = pepy_parsed_new(&pepy_parsed_type, NULL, NULL);
	if (!parsed) {
		PyErr_SetString(pepy_error, "Unable to make new parsed object.");
		return NULL;
	}

	ret = pepy_parsed_init((pepy_parsed *) parsed, args, NULL);
	if (ret < 0) {
		if (ret == -2)
			PyErr_SetString(pepy_error, "Unable to parse PE file.");
		else
			PyErr_SetString(pepy_error, "Unable to init new parsed object.");
		return NULL;
	}

	return parsed;
}

static PyMethodDef pepy_methods[] = {
	{ "parse", pepy_parse, METH_VARARGS, "Parse PE from file." },
	{ NULL }
};

PyMODINIT_FUNC initpepy(void) {
	PyObject *m;

	if (PyType_Ready(&pepy_parsed_type) < 0)
		return;

	m = Py_InitModule3("pepy", pepy_methods, "Python interface to pe-parse.");
	if (!m)
		return;

	pepy_error = PyErr_NewException((char *) "pepy.error", NULL, NULL);
	Py_INCREF(pepy_error);
	PyModule_AddObject(m, "error", pepy_error);

	Py_INCREF(&pepy_parsed_type);
	PyModule_AddObject(m, "pepy_parsed", (PyObject *) &pepy_parsed_type);

	PyModule_AddStringMacro(m, PEPY_VERSION);

	PyModule_AddIntMacro(m, MZ_MAGIC);
	PyModule_AddIntMacro(m, NT_MAGIC);
	PyModule_AddIntMacro(m, NUM_DIR_ENTRIES);
	PyModule_AddIntMacro(m, NT_OPTIONAL_32_MAGIC);
	PyModule_AddIntMacro(m, NT_SHORT_NAME_LEN);
	PyModule_AddIntMacro(m, DIR_EXPORT);
	PyModule_AddIntMacro(m, DIR_IMPORT);
	PyModule_AddIntMacro(m, DIR_RESOURCE);
	PyModule_AddIntMacro(m, DIR_EXCEPTION);
	PyModule_AddIntMacro(m, DIR_SECURITY);
	PyModule_AddIntMacro(m, DIR_BASERELOC);
	PyModule_AddIntMacro(m, DIR_DEBUG);
	PyModule_AddIntMacro(m, DIR_ARCHITECTURE);
	PyModule_AddIntMacro(m, DIR_GLOBALPTR);
	PyModule_AddIntMacro(m, DIR_TLS);
	PyModule_AddIntMacro(m, DIR_LOAD_CONFIG);
	PyModule_AddIntMacro(m, DIR_BOUND_IMPORT);
	PyModule_AddIntMacro(m, DIR_IAT);
	PyModule_AddIntMacro(m, DIR_DELAY_IMPORT);
	PyModule_AddIntMacro(m, DIR_COM_DESCRIPTOR);

	PyModule_AddIntMacro(m, IMAGE_SCN_TYPE_NO_PAD);
	PyModule_AddIntMacro(m, IMAGE_SCN_CNT_CODE);
	PyModule_AddIntMacro(m, IMAGE_SCN_CNT_INITIALIZED_DATA);
	PyModule_AddIntMacro(m, IMAGE_SCN_CNT_UNINITIALIZED_DATA);
	PyModule_AddIntMacro(m, IMAGE_SCN_LNK_OTHER);
	PyModule_AddIntMacro(m, IMAGE_SCN_LNK_INFO);
	PyModule_AddIntMacro(m, IMAGE_SCN_LNK_REMOVE);
	PyModule_AddIntMacro(m, IMAGE_SCN_LNK_COMDAT);
	PyModule_AddIntMacro(m, IMAGE_SCN_NO_DEFER_SPEC_EXC);
	PyModule_AddIntMacro(m, IMAGE_SCN_GPREL);
	PyModule_AddIntMacro(m, IMAGE_SCN_MEM_FARDATA);
	PyModule_AddIntMacro(m, IMAGE_SCN_MEM_PURGEABLE);
	PyModule_AddIntMacro(m, IMAGE_SCN_MEM_16BIT);
	PyModule_AddIntMacro(m, IMAGE_SCN_MEM_LOCKED);
	PyModule_AddIntMacro(m, IMAGE_SCN_MEM_PRELOAD);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_1BYTES);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_2BYTES);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_4BYTES);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_8BYTES);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_16BYTES);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_32BYTES);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_64BYTES);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_128BYTES);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_256BYTES);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_512BYTES);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_1024BYTES);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_2048BYTES);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_4096BYTES);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_8192BYTES);
	PyModule_AddIntMacro(m, IMAGE_SCN_ALIGN_MASK);
	PyModule_AddIntMacro(m, IMAGE_SCN_LNK_NRELOC_OVFL);
	PyModule_AddIntMacro(m, IMAGE_SCN_MEM_DISCARDABLE);
	PyModule_AddIntMacro(m, IMAGE_SCN_MEM_NOT_CACHED);
	PyModule_AddIntMacro(m, IMAGE_SCN_MEM_NOT_PAGED);
	PyModule_AddIntMacro(m, IMAGE_SCN_MEM_SHARED);
	PyModule_AddIntMacro(m, IMAGE_SCN_MEM_EXECUTE);
	PyModule_AddIntMacro(m, IMAGE_SCN_MEM_READ);
	PyModule_AddIntMacro(m, IMAGE_SCN_MEM_WRITE);
}
