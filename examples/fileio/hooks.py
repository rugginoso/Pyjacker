from ctypes import *
from pyjacker import hijacker
import os.path

libc = CDLL('libc.dylib')

f = None

def hj_open(path, flags, mode):
	global f
	f = open(os.path.splitext(path)[0] + '.dump', 'w')
	return libc.open(path, flags, mode)

def write(fd, buf, count):
	f.write(buf[:count])
	return libc.write(fd, buf, count)

def close(fd):
	f.close()
	return libc.close(fd)

hijacker.register_hook('open', hj_open, c_int, c_char_p, c_int, c_int)
hijacker.register_hook('write', write, c_int, c_int, c_char_p, c_int)
hijacker.register_hook('close', close, c_int, c_int)
