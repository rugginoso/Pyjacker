#!/usr/bin/env python
# Copyright (c) 2012, Lorenzo Masini <rugginoso@develer.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from ctypes import *
from string import Template
import re

class FunctionPrototype(object):
	ORIG_POINTER_DECL_TPL = """
static ${ret_type} (*orig_${func_name})(${args}) = NULL;
"""

	ORIG_POINTER_INIT_TPL = """
orig_${func_name} = (${ret_type} (*)(${args_types}))dlsym(RTLD_NEXT, "${func_name}");
"""

	FAKE_FUNC_TPL = """
${ret_type} ${func_name}(${args})
{
	${ret_type} (*func)(${args_types}) = 0;

	func = (${ret_type} (*)(${args_types}))hijack_get_func_ptr("${func_name}");

	if (func == 0)
		func = orig_${func_name};

	return func(${args_names});
}
"""

	regexp = re.compile('^(.+)\s(\w+)[(](.+)[)]$')

	@classmethod
	def from_string(cls, string):
		match = FunctionPrototype.regexp.match(string)
		if match:
			ret_type = match.group(1)
			name = match.group(2)
			args = []
			for arg in [arg.strip() for arg in match.group(3).split(',')]:
				type_and_name = arg.split(' ')
				args.append([" ".join(type_and_name[:-1]), type_and_name[-1]])
			return FunctionPrototype(name, ret_type, args)
		else:
			return None

	def __init__(self, name, ret_type, args):
		self.name = name
		self.ret_type = ret_type
		self.args = args

	def orig_pointer_decl(self):
		return Template(FunctionPrototype.ORIG_POINTER_DECL_TPL).substitute(ret_type=self.ret_type,
		                                                                    func_name=self.name,
		                                                                    args=', '.join(["%s %s" % tuple(lst) for lst in self.args])).strip()

	def orig_pointer_init(self):
		return Template(FunctionPrototype.ORIG_POINTER_INIT_TPL).substitute(ret_type=self.ret_type,
		                                                                    func_name=self.name,
		                                                                    args_types=", ".join([lst[0] for lst in self.args])).strip()

	def fake_func(self):
		return Template(FunctionPrototype.FAKE_FUNC_TPL).substitute(ret_type=self.ret_type,
		                                                            func_name=self.name,
		                                                            args=', '.join(["%s %s" % tuple(lst) for lst in self.args]),
		                                                            args_types=', '.join([lst[0] for lst in self.args]),
		                                                            args_names=', '.join([lst[1] for lst in self.args])).strip()

class HijackerGenerator(object):
	MAIN_TPL = """
/*
 * Copyright (c) 2012, Lorenzo Masini <rugginoso@develer.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of the <organization> nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <Python.h>

#include <stdlib.h>
#include <dlfcn.h>

#define HOOKS_MODULE_ENV "PYJACKER_HOOKS"

static PyObject *hooks_module = NULL;

${orig_pointers_decls}

static unsigned long hijack_get_func_ptr(const char *name)
{
	PyObject *func = PyObject_GetAttrString(hooks_module, name);
	if (func == NULL) {
		PyErr_Print();
		exit(-1);
	}

	PyObject *py_func_ptr = PyObject_GetAttrString(func, "c_ptr");
	if (py_func_ptr == NULL) {
		PyErr_Print();
		exit(-1);
	}

	unsigned long func_addr = PyLong_AsLong(py_func_ptr);
	Py_DECREF(py_func_ptr);
	Py_DECREF(func);

	return func_addr;
}

${fake_funcs}

void __attribute__ ((constructor)) hijack_init(void)
{
	${orig_pointers_inits}

	const char *hooks_module_name = NULL;
	hooks_module_name = getenv(HOOKS_MODULE_ENV);
	if (hooks_module_name == NULL) {
		fprintf(stderr, HOOKS_MODULE_ENV" not set.\\n");
		exit(-1);
	}

	Py_Initialize();

	hooks_module = PyImport_ImportModule(hooks_module_name);

	if (hooks_module == NULL) {
		PyErr_Print();
		exit(-1);
	}
}

void __attribute__ ((destructor)) hijack_finalize(void)
{
	Py_DECREF(hooks_module);
	Py_Finalize();
}
"""

	def __init__(self):
		self.functions = []

	def add_prototype(self, string):
		func = FunctionPrototype.from_string(string.strip())
		if func:
			self.functions.append(func)

	def generate(self):
		orig_pointers_decls = []
		orig_pointers_inits = []
		fake_funcs = []

		for function in self.functions:
			orig_pointers_decls.append(function.orig_pointer_decl())
			orig_pointers_inits.append(function.orig_pointer_init())
			fake_funcs.append(function.fake_func())

		return Template(HijackerGenerator.MAIN_TPL).substitute(orig_pointers_decls='\n'.join(orig_pointers_decls),
			                                       			   orig_pointers_inits='\n'.join(orig_pointers_inits),
			                                                   fake_funcs='\n'.join(fake_funcs)).strip()

generator = HijackerGenerator()

class hook(object):
	def __init__(self, c_prototype, ctypes_ret_type=None, ctypes_args=[]):
		generator.add_prototype(c_prototype)
		self.ctypes_ret_type = ctypes_ret_type
		self.ctypes_args = ctypes_args

	def __call__(self, f):
		args_types = self.ctypes_args
		LIBRARY_HOOK_FUNC = CFUNCTYPE(self.ctypes_ret_type, *args_types)
		hook = LIBRARY_HOOK_FUNC(f)
		f.c_ptr = cast(hook, c_void_p).value
		return f

def launch(command, hooks_file):
	from subprocess import Popen, PIPE
	import sys, os

	PYJACKER_SOURCE = "hijacker.c"
	PYJACKER_LIB = "libhijacker.so"

	try:
		with open("hijacker.c", "w") as f:
			f.write(generator.generate())
	except IOError as e:
		print('[-] Error generating c source: %s' % e)
		sys.exit(-1)
	print('[+] Generated c source for hijacking library')
	
	compile_cmd = ['gcc', PYJACKER_SOURCE, '-o', PYJACKER_LIB, '-shared', '-fPIC', '-Wall', '-O2']
	try:
		output = Popen(['python-config', '--cflags', '--libs'], stdout=PIPE).communicate()[0]
		compile_cmd.extend([arg.strip() for arg in output.replace('\n', ' ').split()])
	except OSError as e:
		print('[-] Error getting compile flags: %s' % e)
		sys.exit(-1)
	print('[+] Got compile flags')

	gcc = Popen(compile_cmd)
	if gcc.wait() != 0:
		print('[-] Error compiling library')
		sys.exit(-1)
	print('[+] Compiled library in %s' % PYJACKER_LIB)

	print('[+] Launcing program\n')
	env = os.environ
	env['LD_PRELOAD'] = os.path.abspath(PYJACKER_LIB)
	env['PYJACKER_HOOKS'] = os.path.splitext(os.path.basename(hooks_file))[0]
	env['PYTHONPATH'] = os.path.dirname(os.path.abspath(hooks_file))
	ret = 0
	try:
		program = Popen(command, env=env)
		ret = program.wait()
	finally:
		os.remove(PYJACKER_SOURCE)
		os.remove(PYJACKER_LIB)
	return ret
