#ifndef _OHY_RELOCATOR_H
#define _OHY_RELOCATOR_H

#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/version.h>

void** sys_call_table = NULL;
void** sys_call_table_arm64 = NULL;

struct ohy_syml {
    unsigned long syscall_number;
    const char* name;
    const void* addr;
};

struct ohy_hook {
    unsigned long syscall_number;
    const char* name;
    void* original;
    void* hooked;
};

__attribute__((unused))
static bool find_symbol_in_exports(struct ohy_syml* symldef)
{
    unsigned long export_addr;

    if (symldef->name == NULL)
        return false;

    export_addr = kallsyms_lookup_name(symldef->name);
    symldef->addr = (void *)export_addr;

    return true;
}

__attribute__((unused))
static bool replace_function(struct ohy_hook* hookdef)
{
    struct ohy_syml sym = {.name = hookdef->name};

    if (hookdef->original == NULL && hookdef->hooked == NULL)
        return false;

    if (find_symbol_in_exports(&sym)) {
         return false;
    }

    hookdef->original = (void *)(sys_call_table_arm64[hookdef->syscall_number]);
    sys_call_table_arm64[hookdef->syscall_number] = (void *)hookdef->hooked;

    return true;
}

__attribute__((unused))
static bool restore_function(struct ohy_hook* hookdef)
{
    if (hookdef->original == NULL && hookdef->hooked == NULL)
        return false;

    sys_call_table_arm64[hookdef->syscall_number] = (void *)hookdef->original;
    return true;
}

__attribute__((unused))
static bool get_syscall_addr(void)
{
    unsigned long addr;
    sys_call_table = NULL;

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
        struct kprobe kp = { .symbol_name = "sys_call_table" };

        if (register_kprobe(&kp) < 0)
            return false;

        addr = (unsigned long) kp.addr;
        sys_call_table_arm64 = (void**) kp.addr;

        unregister_kprobe(&kp);
        return true;
    #else
        addr = (unsigned long) kallsyms_lookup_name ("sys_call_table");

        if (addr) {
            sys_call_table_arm64 = (void**) addr;
            return true;
        } 

        return false;
    #endif
}

#endif