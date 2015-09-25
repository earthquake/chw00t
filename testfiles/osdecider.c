#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

int main()
{
#if __linux__
	printf("Linux\n");
#endif
#if __FreeBSD__
	printf("FreeBSD\n");
#endif
#if __OpenBSD__
	printf("OpenBSD\n");
#endif
#if __DragonFly__
	printf("DragonflyBSD\n");
#endif
#if __NetBSD__
	printf("NetBSD\n");
#endif
#if __APPLE__
	printf("Mac Os X\n");
#endif
#if __sun
	printf("Solaris\n");
#endif
}	
