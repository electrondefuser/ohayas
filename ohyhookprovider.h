#ifndef _OHY_HOOKPROVIDER_H
#define _OHY_HOOKPROVIDER_H

#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <asm/current.h>

#include "ohytracing.h"

int proc_id = 0;

struct ohyhook {
    const char* name;
    void* function;
    void* original;

    unsigned long address;
    struct ftrace_ops ftr_operations;
};

#ifdef PTREGS_SYSCALL_INITIALIZATION

	#define SYSCALL_NAME_INT64(name)   ("__x64_"    name) 	/* 64-BIT INTEL/AMD CPUs */
	#define SYSCALL_NAME_INT32(name)   ("__ia32_"   name) 	/* 32-BIT INTEL/AMD CPUs */
	#define SYSCALL_NAME_ARMV8(name)   ("__arm64_"  name) 	/* 64-BIT ARM CPUs */
	#define SYSCALL_NAME_ARMV7(name)   ("__arm_"    name) 	/* 32-BIT ARM CPUs */

#else
    #define SYSCALL_NAME(name) (name)
#endif

#define CREATE_HOOK(_name, _function, _original)	\
{										 			\
	.name = SYSCALL_NAME(_name), 				    \
	.function = (_function),			 			\
	.original = (_original),			 			\
}

#define USE_FENTRY_OFFSET 0

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
	#define PTREGS_SYSCALL_INITIALIZATION 1
#endif

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5,12,0))
	#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
	#define ftrace_regs pt_regs

	static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs) {
		return fregs;
	}
#endif

static int tracer_resolve_hook_address(struct ohyhook *hook) {
	hook->address = lookup_function_by_name(hook->name);

	if (!hook->address) {
		printk(KERN_ALERT "unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

    #if USE_FENTRY_OFFSET
	    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
    #else
	    *((unsigned long*) hook->original) = hook->address;
    #endif

	return 0;
}

static notrace void tracer_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ftr_operations, struct ftrace_regs *fregs) {
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ohyhook *hook = container_of(ftr_operations, struct ohyhook, ftr_operations);

    #if USE_FENTRY_OFFSET
        regs->pc = (unsigned long) hook->function + MCOUNT_INSN_SIZE;
    #else
        if (!within_module(parent_ip, THIS_MODULE))
            regs->pc = (unsigned long) hook->function;
    #endif
}

static int tracer_insert_hooks(struct ohyhook *hook) {
    unsigned long addr;
	int err;

	err = tracer_resolve_hook_address(hook);
	if (err)
		return err;

    hook->ftr_operations.func  = tracer_callback;
    // hook->ftr_operations.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

	addr = ftrace_location_range(hook->address, hook->address + AARCH64_INSN_SIZE);
    err = ftrace_set_filter_ip(&hook->ftr_operations, addr, 0, 0);
	
    if (err) {
		printk(KERN_ALERT "ftrace_set_filter_ip() has failed with: %d\n", err);
		return err;
	}

    err = register_ftrace_function(&hook->ftr_operations);

    if (err) {
		printk(KERN_ALERT "register_ftrace_func() has failed with: %d\n", err);

		addr = ftrace_location_range(hook->address, hook->address + AARCH64_INSN_SIZE);
		ftrace_set_filter_ip(&hook->ftr_operations, addr, 1, 0);
		return err;
	}

	printk(KERN_ALERT "HOOK CREATED\n", err);
    return 0;
}

static int tracer_remove_hooks(struct ohyhook *hook) {
    unsigned long addr;
	int err;

	err = unregister_ftrace_function(&hook->ftr_operations);
	if (err) {
		printk(KERN_ALERT "unregister_ftrace_function() failed: %d\n", err);
	}

	addr = ftrace_location_range(hook->address, hook->address + AARCH64_INSN_SIZE);
	err = ftrace_set_filter_ip(&hook->ftr_operations, addr, 1, 0);
	if (err) {
		printk(KERN_ALERT "ftrace_set_filter_ip() has failed with: %d\n", err);
	}

	printk(KERN_ALERT "HOOK REMOVED\n", err);
    return 0;
}

#ifdef PTREGS_SYSCALL_INITIALIZATION
	static asmlinkage long (*real_connect)(const struct pt_regs *regs);
	static asmlinkage notrace long hooked_connect(const struct pt_regs *regs) {

		long ret;

		if (proc_id == 0) {
			proc_id = current->pid;
			printk(KERN_ALERT "[INFO] Process ID %i is using SYSCALL Interface \n", proc_id);
			printk(KERN_ALERT "[INFO] Trampoline at %p \n", &hooked_connect);
		}

		printk(KERN_ALERT "[FUNC] CONNECT() invoked\n");;
		ret = real_connect(regs);

		printk(KERN_ALERT "[RETN] VAL: %d\n", ret);
		return ret;
	}

	static asmlinkage long (*real_faccessat)(const struct pt_regs *regs);
	static asmlinkage notrace long hooked_faccessat(const struct pt_regs *regs) {
		
		long ret;

		if (proc_id == 0) {
			proc_id = current->pid;
			printk(KERN_ALERT "[INFO] Process ID %i is using SYSCALL Interface \n", proc_id);
			printk(KERN_ALERT "[INFO] Trampoline at %p \n", &hooked_faccessat);
		}

		printk(KERN_ALERT "[FUNC] FACCESSAT() invoked\n");
		ret = real_faccessat(regs);

		printk(KERN_ALERT "[RETN] VAL: %d\n", ret);
		return ret;
	}
#else
	static asmlinkage long (*real_connect)(int sockfd, struct sockaddr __user *sockadr, int size);
	static asmlinkage long hooked_connect(int sockfd, struct sockaddr __user *sockadr, int size) {

		long ret;

		if (proc_id == 0) {
			proc_id = current->pid;
			printk(KERN_ALERT "[INFO] Process ID %i is using SYSCALL Interface \n", proc_id);
			printk(KERN_ALERT "[INFO] Trampoline at %p \n", &hooked_connect);
		}

		printk(KERN_ALERT "connect()!");

		ret = real_connect(sockfd, sockadr, size);
		return ret;
	}

	static asmlinkage long (*real_faccessat)(int dfd, const char __user *filename, int mode);
	static asmlinkage long hooked_faccessat (int dfd, const char __user *filename, int mode) {

		long ret;

		if (proc_id == 0) {
			proc_id = current->pid;
			printk(KERN_ALERT "[INFO] Process ID %i is using SYSCALL Interface \n", proc_id);
			printk(KERN_ALERT "[INFO] Trampoline at %p \n", &hooked_faccessat);
		}

		printk(KERN_ALERT "[FUNC] FACCESSAT() invoked\n");
		ret = real_faccessat(dfd, filename, mode);

		printk(KERN_ALERT "[RETN] VAL: %d\n", ret);
		return ret;
	}
#endif


struct ohyhook hookdef_faccess1 = {
    .name 		= "sys_faccessat",
	.function 	= hooked_faccessat,
	.original 	= &real_faccessat
};

struct ohyhook hookdef_connect1 = {
    .name 		= "sys_connect",
	.function 	= hooked_connect,
	.original 	= &real_connect
};

static void create_hooks() {
    tracer_insert_hooks(&hookdef_faccess1);
	tracer_insert_hooks(&hookdef_connect1);
}

static void remove_hooks() {
    tracer_remove_hooks(&hookdef_faccess1);
	tracer_remove_hooks(&hookdef_connect1);
}

#endif