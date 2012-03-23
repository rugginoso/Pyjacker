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
import re
from string import Template


class FunctionPrototype(object):
	INCLUDE_TPL = """
#include <${include}>
"""

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

	regexp = re.compile('^(.+)\s(\w+)[(](.+)[)]\s(.*)$')

	@classmethod
	def from_string(cls, string):
		match = FunctionPrototype.regexp.match(string)
		if match:
			ret_type = match.group(1)
			name = match.group(2)
			includes = [include.strip() for include in match.group(4).split(',')]
			args = []
			for arg in [arg.strip() for arg in match.group(3).split(',')]:
				type_and_name = arg.split(' ')
				args.append([" ".join(type_and_name[:-1]), type_and_name[-1]])
			return FunctionPrototype(name, ret_type, args, includes)
		else:
			return None

	def __init__(self, name, ret_type, args, includes):
		self.name = name
		self.ret_type = ret_type
		self.args = args

		self.include_files = includes

	def includes(self):
		lines = []
		for include in self.include_files:
			lines.append(Template(FunctionPrototype.INCLUDE_TPL).substitute(include=include).strip()) 
		return lines

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

${includes}


#define HOOKS_MODULE_ENV "PYJACKER_HOOKS"

static PyObject *hooks_module = NULL;
static PyObject *hijacker = NULL;

${orig_pointers_decls}

static unsigned long hijack_get_func_ptr(const char *name)
{
	PyObject *func_ret = NULL;	
	unsigned long func_addr = 0;

	/*
	 * Pre-initialization request, fallback to default implementation
	 */
	if (hijacker == NULL)
		return 0;

	func_ret = PyObject_CallMethod(hijacker, "hook_ptr", "s", name);
	if (func_ret == NULL) {
		fprintf(stderr, "Error calling method hijacker.hook_ptr for %s\\n", name);
		exit(-1);
	}

	func_addr = PyLong_AsLong(func_ret);
	Py_DECREF(func_ret);

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

	hijacker = PyObject_GetAttrString(hooks_module, "hijacker");
	if (hijacker == NULL) {
		fprintf(stderr, "Error retriving hijacker\\n");
		exit(-1);
	}
}

void __attribute__ ((destructor)) hijack_finalize(void)
{
	Py_DECREF(hijacker);
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
		known_includes = set()
		includes = []
		orig_pointers_decls = []
		orig_pointers_inits = []
		fake_funcs = []

		for function in self.functions:
			for include in function.includes():
				if not include: continue
				if include in known_includes: continue
				includes.append(include)
				known_includes.add(include)
			orig_pointers_decls.append(function.orig_pointer_decl())
			orig_pointers_inits.append(function.orig_pointer_init())
			fake_funcs.append(function.fake_func())

		return Template(HijackerGenerator.MAIN_TPL).substitute(includes='\n'.join(includes),
			                                       					 orig_pointers_decls='\n'.join(orig_pointers_decls),
			                                       					 orig_pointers_inits='\n'.join(orig_pointers_inits),
			                                                         fake_funcs='\n'.join(fake_funcs)).strip()
