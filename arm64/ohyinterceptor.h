#ifndef _OHY_INTERCEPTOR_H
#define _OHY_INTERCEPTOR_H

#include "linux/init.h"
#include "asm/unistd.h"
#include "linux/slab.h"
#include "linux/uaccess.h"
#include "linux/socket.h"
#include "linux/kallsyms.h"
#include "linux/in.h"
#include "linux/in6.h"
#include "linux/string.h"
#include "linux/prctl.h"
#include "linux/random.h"

#include "../ohylog.h"
#include "../ohyutils.h"
#include "../ohyprocess.h"

void **sys_call_table64 = NULL;

#define FRIDA_GADGET_ARTIFACT   "libFridaGadget.so"
#define FRIDA_FOLDER            "re.frida.server"
#define FRIDA_GUMJS_LOOP        "gum-js-loop"
#define FRIDA_NAME              "frida"
#define GMAIN_LOOP              "gmain"
#define PROC_MAPS               "/proc/self/maps"
#define PROC_TASK               "/proc/self/task"

#define IPv4     AF_INET
#define IPv6     AF_INET6

asmlinkage long (*old_connect)      (int fd, struct sockaddr __user* addr, int addrlen);
asmlinkage long (*old_bind)         (int fd, struct sockaddr __user* addr, int addrlen);
asmlinkage long (*old_faccessat)    (int dfd, const char __user *filename, int mode);
asmlinkage long (*old_openat)       (int dfd, const char __user *filename, int flags, umode_t mode);
asmlinkage long (*old_read)         (unsigned int fd, char __user *buf, size_t count);

struct sockaddr_data
{
    struct sockaddr_storage addr;
};

int scan_process(const struct task_struct* t, const char* name)
{
    int i = 0;
    int pid = 0;
    struct ohy_threads* threads_proc;

    if (t != NULL)
    {
        threads_proc = get_threads_pid(t);
        if (threads_proc != NULL)
        {
            for (i = 0; i < 100; i++) {
                printk(KERN_ALERT "PROC_THREADS: %i: %s", threads_proc[i].thread_id, threads_proc[i].thread_name);
            }

            pid = get_frida_gadget_pid(threads_proc, name);

            printk(KERN_ALERT "PROC_THREADS_FRIDA: %i", pid);
            kfree(threads_proc);

            return pid;
        }
    }

    return 0;
}

void generate_random_string(char *dest, size_t length)
{
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    while (length-- > 0) {
        int random_index = get_random_int() % (sizeof(charset) - 1);
        *dest++ = charset[random_index];
    }
}

void search_and_replace(char *buffer, size_t count)
{
    const char *terms[] = {"frida-gadget", "gmain", "gum-js-loop"};
    const int num_terms = sizeof(terms) / sizeof(terms[0]);
    int i = 0;

    for (i = 0; i < num_terms; ++i) {
        char *pos = buffer;
        size_t term_len = strlen(terms[i]);

        while ((pos = strstr(pos, terms[i])) != NULL) {
            if (pos + term_len <= buffer + count) {  // Ensure we do not go out of bounds
                char random_chars[term_len + 1];
                generate_random_string(random_chars, term_len);
                memcpy(pos, random_chars, term_len);
                pos += term_len;
            } else {
                break;  // Stop if the term cannot be fully replaced due to buffer limits
            }
        }
    }
}

__attribute__((unused))
unsigned long asmlinkage new_connect(int fd, struct sockaddr __user* addr, int addrlen)
{
    int is_hdfc, is_axis;
    int cp_result;

    struct sockaddr_data    *captured_addr;
    struct sockaddr_in      *s_inaddr4;
    struct sockaddr_in6     *s_inaddr6;
    struct task_struct      *parent_proc;

    unsigned short port;
    int ret;

    captured_addr = kmalloc(sizeof(struct sockaddr_data), GFP_KERNEL);
    cp_result = copy_from_user(&captured_addr->addr, addr, sizeof(struct sockaddr_storage));

    if (cp_result)
    {
        kfree(captured_addr);
        return -EFAULT;
    }

    switch (captured_addr->addr.ss_family)
    {
        case IPv4:
            s_inaddr4 = (struct sockaddr_in*)(&captured_addr->addr);
            port = ntohs(s_inaddr4->sin_port);
            parent_proc = current->parent;

            if (parent_proc)
            {
                printk(KERN_ALERT "ohayas_interceptor: Connect(%i), Proc: %s, IPv4 detected, PORT: %u", current->pid, parent_proc->comm, port);
                
                is_hdfc = strstr(parent_proc->comm, "hdfc") != NULL;
                is_axis = strstr(parent_proc->comm, "axis") != NULL;

                if (is_hdfc || is_axis)
                {
                    if (port == 27042) {
                        // scan_process();
                        printk(KERN_ALERT "ohayas_interceptor: FRIDA SCAN:= [27042], DROPPING PACKET, CONNECT()");
                        ret = old_connect(fd, addr, addrlen);
                        return ret;
                    }
                }
            }

            ret = old_connect(fd, addr, addrlen);
            return ret;

        case IPv6:
            s_inaddr6 = (struct sockaddr_in6*)(&captured_addr->addr);
            port = ntohs(s_inaddr6->sin6_port);
            parent_proc = current->parent;

            if (parent_proc)
            {
                printk(KERN_ALERT "ohayas_interceptor: Connect(%i), Proc: %s, IPv4 detected, PORT: %u", current->pid, parent_proc->comm, port);
                
                is_hdfc = strstr(parent_proc->comm, "hdfc") != NULL;
                is_axis = strstr(parent_proc->comm, "axis") != NULL;
                
                if (is_hdfc || is_axis)
                {
                    if (port == 27042) {
                        // scan_process();

                        printk(KERN_ALERT "ohayas_interceptor: FRIDA SCAN:= [27042], DROPPING PACKET, CONNECT()");
                        ret = old_connect(fd, addr, addrlen);
                        return ret;
                    }
                }
            }
    
            ret = old_connect(fd, addr, addrlen);
            return ret;
    }

    kfree(captured_addr);

    ret = old_connect(fd, addr, addrlen);
    return ret;
}

__attribute__((unused))
unsigned long asmlinkage new_bind(int fd, struct sockaddr __user* addr, int addrlen)
{
    int is_hdfc, is_axis;
    int cp_result;

    struct task_struct      *parent_process;

    struct sockaddr_data    *captured_addr;
    struct sockaddr_in      *s_inaddr4;
    struct sockaddr_in6     *s_inaddr6;

    unsigned short port;
    int ret;

    captured_addr = kmalloc(sizeof(struct sockaddr_data), GFP_KERNEL);
    cp_result = copy_from_user(&captured_addr->addr, addr, sizeof(struct sockaddr_storage));

    if (cp_result)
    {
        kfree(captured_addr);
        return -EFAULT;
    }

    switch (captured_addr->addr.ss_family)
    {
        case IPv4:
            s_inaddr4 = (struct sockaddr_in*)(&captured_addr->addr);
            port = ntohs(s_inaddr4->sin_port);
            parent_process = current->parent;

            if (parent_process)
            {
                printk(KERN_ALERT "ohayas_interceptor: Bind(%i), Proc: %s, IPv4 detected, PORT: %u", current->pid, parent_process->comm, port);

                is_hdfc = strstr(parent_process->comm, "hdfc") != NULL;
                is_axis = strstr(parent_process->comm, "axis") != NULL;

                if (is_hdfc || is_axis)
                {
                    if (port == 27042) 
                    {
                        int gadget_pid = scan_process(current, "wdmjobgadget");
                        int gdbus_pid = scan_process(current, "giazz");

                        printk(KERN_ALERT "ohayas_interceptor: FRIDA_GADGET_PID := [%i], GDBUS_PID := [%i]", gadget_pid, gdbus_pid);
                        printk(KERN_ALERT "ohayas_interceptor: CURRENT_PORT_ACCESS_PID := [%i]", current->pid);
                     
                        if (gadget_pid == current->pid || gdbus_pid == current->pid) {
                            printk(KERN_ALERT "ohayas_interceptor: PORT_ACCESS_GRANTED TO := [%i]", current->pid);
                            ret = old_bind(fd, addr, addrlen);
                            kfree(captured_addr);
                            return ret;
                        } else {
                            printk(KERN_ALERT "ohayas_interceptor: FRIDA SCAN:= [27042], DROPPING PACKET, BIND(), PID: %i", current->pid);
                            kfree(captured_addr);
                            return 0;
                        }
                    }
                }
            }

            ret = old_bind(fd, addr, addrlen);
            kfree(captured_addr);
            return ret;

        case IPv6:
            s_inaddr6 = (struct sockaddr_in6*)(&captured_addr->addr);
            port = ntohs(s_inaddr6->sin6_port);
            parent_process = current->parent;

            if (parent_process)
            {
                printk(KERN_ALERT "ohayas_interceptor: Bind(%i), Proc: %s, IPv6 detected, PORT: %u", current->pid, parent_process->comm, port);
                
                is_hdfc = strstr(parent_process->comm, "hdfc") != NULL;
                is_axis = strstr(parent_process->comm, "axis") != NULL;

                if (is_hdfc || is_axis)
                {
                    if (port == 27042)
                    {
                        int gadget_pid = scan_process(current, "wdmjobgadget");
                        int gdbus_pid = scan_process(current, "giazz");

                        printk(KERN_ALERT "ohayas_interceptor: FRIDA_GADGET_PID := [%i], GDBUS_PID := [%i]", gadget_pid, gdbus_pid);
                        printk(KERN_ALERT "ohayas_interceptor: CURRENT_PORT_ACCESS_PID := [%i]", current->pid);
                     
                        if (gadget_pid == current->pid || gdbus_pid == current->pid) {
                            printk(KERN_ALERT "ohayas_interceptor: PORT_ACCESS_GRANTED TO := [%i]", current->pid);
                            ret = old_bind(fd, addr, addrlen);
                            kfree(captured_addr);
                            return ret;
                        } else {
                            printk(KERN_ALERT "ohayas_interceptor: FRIDA SCAN:= [27042], DROPPING PACKET, BIND(), PID: %i", current->pid);
                            kfree(captured_addr);
                            return 0;
                        }
                    }
                }
            }

            ret = old_bind(fd, addr, addrlen);
            kfree(captured_addr);
            return ret;
    }

    ret = old_bind(fd, addr, addrlen);
    kfree(captured_addr);

    return ret;
}

__attribute__((unused))
unsigned long asmlinkage new_faccessat(int dfd, const char __user *filename, int mode)
{
    struct task_struct *parent_process;
    int frida_gadget_check, frida_folder, frida;
    int is_hdfc, is_axis;
    int ret = -1;

    if (!ohy_get_proc_uid())
    {
        ret = old_faccessat(dfd, filename, mode);
        return ret;
    }

    parent_process = current->parent;

    if (parent_process)
    {
        is_hdfc = strstr(parent_process->comm, "hdfc") != NULL;
        is_axis = strstr(parent_process->comm, "axis") != NULL;

        if (is_hdfc || is_axis)
        {
            char bufname[256] = {0};
            
            strncpy_from_user(bufname, filename, 255);
            printk(KERN_ALERT "[FUNC] ohayas_interceptor: FACCESSAT(%s) TASKID: %i, MAINID: %i", bufname, current->pid, parent_process->pid);

            frida_gadget_check = strstr(bufname, FRIDA_GADGET_ARTIFACT) != NULL;
            frida_folder = strstr(bufname, FRIDA_FOLDER) != NULL;
            frida = strstr(bufname, FRIDA_NAME) != NULL;

            if (frida_gadget_check || frida_folder || frida)
            {
                printk(KERN_ALERT "ohayas_interceptor: Frida Checks Found!", bufname);
                return -2;
            }
        
            ret = old_faccessat(dfd, filename, mode);
            return ret;
        }
    }

    ret = old_faccessat(dfd, filename, mode);
    return ret;
}

__attribute__((unused))
unsigned long asmlinkage new_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
    struct task_struct *parent_process;
    int is_hdfc, is_axis, ret;

    if (!ohy_get_proc_uid())
    {
        ret = old_openat(dfd, filename, flags, mode);
        return ret;
    }

    parent_process = current->parent;

    if (parent_process)
    {
        is_hdfc = strstr(parent_process->comm, "hdfc") != NULL;
        is_axis = strstr(parent_process->comm, "axis") != NULL;

        if (is_hdfc || is_axis)
        {
            char bufname[256] = {0};
            copy_from_user(bufname, filename, 255);

            if (strstr(bufname, FRIDA_GADGET_ARTIFACT))
            {
                printk(KERN_ALERT "ohayas_interceptor: Frida Gadget Detected!!", bufname);
                return -1;
            }

            if (strstr(bufname, FRIDA_FOLDER))
            {
                printk(KERN_ALERT "ohayas_interceptor: Frida Folder Detected!!", bufname);
                return -1;
            }

            printk(KERN_ALERT "[FUNC] ohayas_interceptor: OPENAT(%i) Path: %s", current->pid, bufname);
            ret = old_openat(dfd, filename, flags, mode);
            return ret;
        }
    }

    ret = old_openat(dfd, filename, flags, mode);
    return ret;
}

__attribute__((unused))
unsigned long asmlinkage new_read(unsigned int fd, char __user *buf, size_t count)
{
    int ret = old_read(fd, buf, count);

    if (ret > 0)
    {
        size_t copy_size = ret < count ? ret : count;    
        struct task_struct *parent_process;
        int is_hdfc, is_axis;

        if (!ohy_get_proc_uid())
        {
            return ret;
        }

        parent_process = current->parent;

        if (parent_process)
        {
            is_hdfc = strstr(parent_process->comm, "hdfc") != NULL;
            is_axis = strstr(parent_process->comm, "axis") != NULL;

            if (is_hdfc || is_axis)
            {
                char *bufname = kmalloc(count + 1, GFP_KERNEL);
                if (copy_from_user(bufname, buf, count))
                {
                    kfree(bufname);
                    return -EFAULT;
                }

                search_and_replace(bufname, copy_size);
                if (copy_to_user(buf, bufname, copy_size))
                {
                    kfree(bufname);
                    return -EFAULT;
                }
            
                kfree(bufname);
            }

            return ret;
        }
    }
    return ret;
}

__attribute__((unused))
static int hook_init(void)
{
    void** addr = (void**) kallsyms_lookup_name("sys_call_table");
    sys_call_table64 = addr;

    old_faccessat       = (void*)(sys_call_table64[__NR_faccessat]);
    old_openat          = (void*)(sys_call_table64[__NR_openat]);
    old_connect         = (void*)(sys_call_table64[__NR_connect]);
    old_bind            = (void*)(sys_call_table64[__NR_bind]);
    // old_read            = (void*)(sys_call_table64[__NR_read]);

    sys_call_table64[__NR_faccessat]        = (void*)new_faccessat;    
    sys_call_table64[__NR_openat]           = (void*)new_openat;
    sys_call_table64[__NR_connect]          = (void*)new_connect;
    sys_call_table64[__NR_bind]             = (void*)new_bind;
    // sys_call_table64[__NR_read]             = (void*)new_read;

    return 0;
}

#endif