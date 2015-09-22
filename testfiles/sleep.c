#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main()
{
	while (1)
	{
		printf("my pid: %d\n", getpid());
		sleep(1);
	}
	return 0;
}
