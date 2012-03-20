from ctypes import *
from pyjacker import hijacker

libc = CDLL('libc.so.6')

def write(fd, buf, count):
	print "hooking write"
	print fd
	print buf
	print count

	return libc.write(fd, buf, count)

hijacker.register_hook("write", write, c_int, c_int, c_char_p, c_int)
