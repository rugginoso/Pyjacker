#!/usr/bin/env python
from ctypes import *
import pyjacker

libc = CDLL('libc.so.6')

@pyjacker.hook('int puts(const char* string)', ctypes_ret_type=c_int, ctypes_args=[c_char_p])
def puts(string):
	string = string + " hijacked"
	return libc.puts(string)

if __name__ == "__main__":
	import sys
	pyjacker.launch(sys.argv[1:], __file__)
