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
import re
from string import Template, strip

HOOKS_LIST = "hooks.list"

MAIN_TPL = """
/*
 * Copyright (c) <year>, <copyright holder>
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
#include <stdlib.h>
#include <dlfcn.h>

#include <Python.h>

${hooks_includes}


#define HOOKS_MODULE_ENV "PYJACKER_HOOKS"

static PyObject *hooks_module = NULL;
static PyObject *hijacker = NULL;

${orig_pointers_decls}
${func_aliases}

static unsigned long hijack_get_func_ptr(const char *name)
{
	PyObject *func_ret = NULL;	
	unsigned long func_addr = 0;

	func_ret = PyObject_CallMethod(hijacker, "hook_ptr", "s", "write");
	if (func_ret == NULL) {
		printf("Error calling method hijacker.hook_ptr\\n");
		exit(-1);
	}

	func_addr = PyLong_AsLong(func_ret);
	Py_DECREF(func_ret);

	return func_addr;
}

${fake_funcs}

void __attribute__ ((constructor)) hijack_init(void)
{
	const char *hooks_module_name = NULL;

	printf("Initializing hijacker... ");

	hooks_module_name = getenv(HOOKS_MODULE_ENV);
	if (hooks_module_name == NULL) {
		printf("\\n"HOOKS_MODULE_ENV" not set.");
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
		printf("Error retriving hijacker\\n");
		exit(-1);
	}

	${orig_pointers_inits}

	printf("done.\\n");
}

void __attribute__ ((destructor)) hijack_finalize(void)
{
	printf("Finalizing hijacker... ");

	Py_DECREF(hijacker);
	Py_DECREF(hooks_module);
	Py_Finalize();

	printf("done.\\n");
}
"""

INCLUDE_TPL = """
#include <${include}>
"""

ORIG_POINTER_DECL_TPL = """
static ${ret_type} (*orig_${func_name})(${args}) = NULL;
"""

ORIG_POINTER_INIT_TPL = """
orig_${func_name} = (${ret_type} (*)(${args_types}))dlsym(RTLD_NEXT, "${func_name}");
"""

FUNC_ALIAS_TPL = """
${ret_type} ${func_name}(${args}) __attribute__ ((weak, alias("fake_${func_name}")));
"""

FAKE_FUNC_TPL = """
${ret_type} fake_${func_name}(${args})
{
	${ret_type} (*func)(${args_types}) = 0;

	func = (${ret_type} (*)(${args_types}))hijack_get_func_ptr("${func_name}");

	if (func == 0)
		func = orig_${func_name};

	return func(${args_names});
}
"""

lines = []

with open(HOOKS_LIST, "r") as f:
	lines = f.readlines()

regexp = re.compile("^\+\s(.+)\s(\w+)[(](.+)[)]\s(.*)$")

functions = []
for line in lines:
	if line[0] == '#': continue
	if line[0] == '+':
		match = regexp.match(line)
		if match:
			function = {}
			function['return-type'] = match.group(1)
			function['function-name'] = match.group(2)
			function['includes'] = [strip(include) for include in match.group(4).split(',')]
			function['args'] = []
			args = [strip(arg) for arg in match.group(3).split(',')]
			for arg in args:
				type_and_name = arg.split(' ')
				function['args'].append([" ".join(type_and_name[:-1]), type_and_name[-1]])
			functions.append(function)
		else:
			print 'Wrong line: "%s"' % line


hooks_includes = []
orig_pointers_decls = []
orig_pointers_inits = []
func_aliases = []
fake_funcs = []

for function in functions:
	data = {}
	data['func_name'] = function['function-name']
	data['ret_type'] = function['return-type']
	data['args'] = ", ".join(["%s %s" % tuple(lst) for lst in function['args']])
	data['args_types'] = ", ".join([lst[0] for lst in function['args']])
	data['args_names'] = ", ".join([lst[1] for lst in function['args']])

	hooks_includes.extend(function['includes'])
	orig_pointers_decls.append(Template(ORIG_POINTER_DECL_TPL).substitute(data))
	orig_pointers_inits.append(Template(ORIG_POINTER_INIT_TPL).substitute(data))
	func_aliases.append(Template(FUNC_ALIAS_TPL).substitute(data))
	fake_funcs.append(Template(FAKE_FUNC_TPL).substitute(data))

known_includes = set()
includes = []

for include in hooks_includes:
	if not include: continue
	if include in known_includes: continue
	includes.append(Template(INCLUDE_TPL).substitute(include=include))
	known_includes.add(include)

main = Template(MAIN_TPL).substitute(hooks_includes='\n'.join(includes),
	                                 orig_pointers_decls='\n'.join(orig_pointers_decls),
	                                 orig_pointers_inits='\n'.join(orig_pointers_inits),
	                                 func_aliases='\n'.join(func_aliases),
	                                 fake_funcs='\n'.join(fake_funcs))

with open('pyjacker.c', 'w') as f:
	f.write(strip(main))
