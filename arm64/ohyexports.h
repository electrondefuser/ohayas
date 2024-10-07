#ifndef _OHY_EXPORTS_H
#define _OHY_EXPORTS_H

#include "asm/unistd.h"
#include "linux/kernel.h"

/* pree-defined syscall exports */

asmlinkage long (*kern_connect)      (int fd, struct sockaddr __user* addr, int addrlen);
asmlinkage long (*kern_faccessat)    (int dfd, const char __user *filename, int mode);
asmlinkage long (*kern_openat)       (int dfd, const char __user *filename, int flags, umode_t mode);
asmlinkage long (*kern_open)         (const char __user *filename, int flags, umode_t mode);
asmlinkage long (*kern_access)       (const char __user *filename, int mode);
asmlinkage long (*kern_readlinkat)   (int dfd, const char __user *path, char __user *buf, int bufsiz);
asmlinkage long (*kern_read)         (unsigned int fd, char __user *buf, size_t count);
asmlinkage long (*kern_exit)         (pid_t pid, int sig);
asmlinkage long (*kern_write)        (unsigned int fd, const char __user *buf,size_t count);
asmlinkage long (*kern_ptrace)       (long request, long pid, unsigned long addr, unsigned long data);

/* user-defined syscall exports */

asmlinkage long (*kern_tgkill)       (pid_t tgid, pid_t pid, int sig);
asmlinkage long (*kern_tkill)        (pid_t pid, int sig);

#endif