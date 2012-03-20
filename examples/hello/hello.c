#include <stdio.h>
#include <string.h>

#define GREETING "hello world!\n"

int main(int argc, char *argv[])
{
	write(0, GREETING, strlen(GREETING));
	
	return 0;
}

