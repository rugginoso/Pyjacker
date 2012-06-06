from ctypes import *
import pyjacker
import os.path

libc = CDLL('libc.so.6')

f = None
pyopen = open

@pyjacker.hook('int open(const char* path, int flags, int mode)', ctypes_ret_type=c_int, ctypes_args=(c_char_p, c_int, c_int))
def open(path, flags, mode):
	global f
	f = pyopen(os.path.splitext(path)[0] + '.dump', 'w')
	return libc.open(path, flags, mode)

@pyjacker.hook('ssize_t write(int fd, const void* buf, size_t count)', ctypes_ret_type=c_long, ctypes_args=(c_int, c_char_p, c_ulong))
def write(fd, buf, count):
	f.write(buf[:count])
	return libc.write(fd, buf, count)

@pyjacker.hook('int close(int fd)', ctypes_ret_type=c_int, ctypes_args=[c_int])
def close(fd):
	f.close()
	return libc.close(fd)

if __name__ == "__main__":
	import sys
	pyjacker.launch(sys.argv[1:], __file__)

