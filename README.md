# chw00t: chroot escape tool
## What’s this tool?
This tool can help you escape from chroot environments. Even though chroot is not a security feature in any Unix systems, it is misused in a lot of setups. With this tool there is a chance that you can bypass this barrier.

## Was it reported to the vendors?
Yes it was. Nobody cares. Chroot is not a security feature, so it should not be used as one. DragonFlyBSD already fixed the NULL pointer dereference bug.
The tool does not work against NetBSD. It has a nice, but probably very slow check that helps defending against chroot bypasses.

## How does this tool works?
Pretty simple. Black Magic. Seriously!

## Got that, but how does it work?
There are several scenarios where it can be useful to escape chroots, but most (not all) of them requires elevated privileges. However, most of the implemented techniques are based on the same technique.  
All processes have two important properties when it comes to chroot: Current Working Directory (CWD) and Root. CWD can be changed easily, for example by the “cd” command. Changing root is much harder. One of the ways to change it is by calling the chroot() syscall or the chroot system tool, but both requires root privilege. When you have your root privilege, then you can call the chroot() syscall and change your process’ Root directory in the process’ property structure (all children processes inherit the Root and CWD properties). Let’s call this new root vnode the root barrier.  
In order to escape the chrooted environment, the ultimate goal here is somehow to move your directory out of the chrooted environment, through the root barrier. Once your directory is out of the chrooted environment, your directory is above the process’ root (root barrier) in the filesystems tree structure, and you broke out of chroot. By addressing the directories relatively, the lookup() system function (which handles all the path-to-vnode translation) will find the original root because that is the last root barrier it can find (the process’ root barrier now is below your CWD in the tree).

## Which techniques are supported?
>NOTE: All techniques presume that you have the right privilege level and you are in the chrooted environment.

### -0 Classic
>Root privilege: NEEDED

Well known technique, everybody knows, the one that everyone refers to.  
The tool creates a new directory and calls the chroot() syscall on it. The kernel will not change the CWD (system tool does change), so the CWD will be above of the root barrier of the process.

* **Bypasses:** Linux, Solaris, Mac OS X
* **DoS:** DragonFlyBSD 4.0.5 and below tested


### -1 Classic with saved file descriptor
>Root privilege: NEEDED

Same as the Classic technique, but before calling the chroot() syscall, the tool saves the file descriptor of the original CWD, just to make sure having it in case the syscall is changed and changes the CWD.

* **Bypasses:** Linux, Solaris, Mac OS X


### -2 File descriptor passing via Unix Domain Socket (UDS)
>Root privilege: NEEDED

The tool creates a directory then forks. The child process cd’ing into the new directory and calls the chroot() syscall. Now it has two separated chroots under each other. It then sets up a Unix Domain Socket that is capable for file descriptor passing. The parent process passes the parent root barrier (which is above of the root of the child) to the child. The child then has a file descriptor on a directory above of its root barrier. Calling fchdir() we are out of the chrooted environment.  

On **Linux** there is a way to create anonymous UDSs, so there is no need touching the filesystem for passing the file descriptor. However FreeBSD/OpenBSD does not support anonymous UDSs.  
While Linux and some other systems are using simple structures for storing these properties, 
**FreeBSD** stores root barriers (resulted from chrooting/creating jails) in a linked list, this way it is only possible to bypass the latest barrier. To overcome FreeBSD’s solution, we need a UDS out of the chroot from the “real” environment.  
The technique **does not work** at the moment on **OpenBSD** because of some mysterious problems.

* **Bypasses:** Linux, Solaris, Mac OS X
* **Partly bypasses:** FreeBSD (chroot and jail)
* **DoS:** DragonFlyBSD


### -3 Procfs magic
>Root privilege: NEEDED

The tool tries to mount procfs into a directory than crawls all the processes for a root or cwd entry. 

* **Bypasses:** Linux, Solaris

### -4 Mount root again
>Root privilege: NEEDED

```sh
WARNING: this feature can be dangerous on live systems, because it mounts
the root partition twice!
```

The tool crawls for all the possible block devices that can have useful data on it and tries to mount it. Hopefully the root partition is found and can be mounted.

* **Bypasses:** Linux

### -5 Move-out-of-chroot
>Root privilege: MIGHT needed

This technique was found by me, pretty easy and can be used without shell access (e.g. FTP, SCP, etc.).  
The tool creates a directory then forks. The child process cd’ing into the new directory and calls the chroot() syscall. Now it has two separated chroots under each other. The child process creates a new directory under the child root barrier and cd’ing into that again. The parent process moves out the child CWD, above the child root barrier, then the child process escaped.

Remember? Linux and some others stores the properties in a struct. **FreeBSD** does store it in the linked list, so the child only escapes the child root barrier, but the parent root barrier. The tool does not leave the original chroot, but could leave it by external help from the original system by moving that directory above of the parent root barrier.  
**OpenBSD** does not let to chroot() after escaping the root barrier, but filesystem operations are allowed (reading files, listing directories).

* **Bypasses:** Linux, OpenBSD, Solaris, Mac OS X
* **Partly bypasses:** FreeBSD (chroot and jail)
* **DoS:** DragonFlyBSD

### -6/-7 Ptrace
>Root privilege: NOT needed

Most fun technique ever. With the ptrace() syscall the tool attaches on a specified PID and replaces the running code with a bind shellcode, then connects to the port. A process is needed outside of the chroot.

* **Bypasses:** Linux, FreeBSD (chroot), OpenBSD
* **Party bypasses:** Ubuntu (only root can attach to other processes)

### -9 Finding open file descriptor
>Root privilege: NEEDED

This feature is mostly for demo purposes. In case the attacker exploits a buffer overflow vulnerability to achieve remote code execution and that exploitable process is chrooted in a bad way, there can be some open file descriptors in the FD table that point out to directories above the root barrier. This feature tries to reveal that possibility. This is almost the same as the Classic FD and UDS technique.

## How to compile the source
Most probably you want to use the tool on a chrooted environment, where no libraries/shared objects (or just a few of them) will be installed. In this case it is better to compile the tool as static:
\# gcc chw00t.c -o chw00t -static

If you are planning to compile it on solaris, you should link the socket library as well:
\# gcc chw00t.c -o chw00t -static -lsocket


