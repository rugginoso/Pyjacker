VERSION = 0.1

TARGET = libpyjacker.so.$(VERSION)
OBJS = pyjacker.o
CC = gcc
CFLAGS = -fPIC -Wall -O2 -g -I/usr/include/python2.7
SHAREDFLAGS = -shared -W1,-soname,pyjacker.so.0
LIBS = -lc -ldl -lpython2.7

all: $(TARGET)

%.o: %.c
	$(CC) -I. $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(SHAREDFLAGS) $(OBJS) -o $(TARGET) $(LIBS)

clean:
	rm -f $(OBJS) $(TARGET)
