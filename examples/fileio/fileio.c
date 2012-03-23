#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#define GREETING "hello world\n"

int main(int argc, char *argv)
{
	int fd = open("test.txt", O_WRONLY | O_CREAT, 0666);

	write(fd, GREETING, strlen(GREETING));

	close(fd);

	return 0;
}
