#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

int main()
{	
	setresgid(1002,1002,1002);
	setresuid(1000,1000,1000);
	return execvp("/bin/bash",  NULL);
}
