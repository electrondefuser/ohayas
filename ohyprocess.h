#ifndef _OHY_PROCESS_H
#define _OHY_PROCESS_H

#include "linux/kernel.h"
#include "linux/module.h"
#include "linux/init.h"
#include "linux/sched.h"
#include "linux/slab.h"
#include "linux/signal.h"
#include "linux/sched.h"

#include "ohyutils.h"

struct ohy_process
{
    size_t pid;
    char process_name[16];
    struct task_struct* proc_task_info;
};

struct ohy_threads
{
    size_t thread_id;
    char thread_name[16];
};

struct ohy_process* current_proc = {0};

__attribute__((unused))
void set_process(struct ohy_process* process)
{
    current_proc = process;
}

__attribute__((unused))
int get_total_threads(const struct task_struct* proc)
{
    struct task_struct* proc_thread;
    int t_count = 0;
    
    for_each_thread(proc, proc_thread)
        t_count += 1;

    return t_count;
}

__attribute__((unused))
int get_frida_gadget_pid(struct ohy_threads* th, const char* name)
{  
    int i = 0;
    int struct_size = 100;

    for (i = 0; i < struct_size; i++)
    {
        if (strstr(th[i].thread_name, name))
            return th[i].thread_id;
    }

    return 0;
}

__attribute__((unused))
struct ohy_process* get_process(void)
{
    return current_proc;
}

__attribute__((unused))
void get_all_running_process(void)
{
    struct task_struct *task_child;
    struct task_struct *t;
    struct list_head *l;

    for_each_process(t)
    {
        if (strstr(t->comm, "main"))
        {
            list_for_each(l, &t->children)
            {
                task_child = list_entry(l, struct task_struct, sibling);
                printk(KERN_ALERT "PROCESS: %s, PID %i", task_child->comm, task_child->pid);
            }
        }
    }
}

__attribute__((unused))
struct ohy_process* get_process_by_name(const char* name)
{
    struct task_struct *task;
    struct ohy_process* process_information = kmalloc(sizeof(struct ohy_process), GFP_KERNEL);

    for_each_process(task)
    {
        if (strstr(task->comm, name))
        {
            strncpy(process_information[0].process_name, task->comm, sizeof(task->comm));
            process_information[0].proc_task_info = task;
            process_information[0].pid = task->pid;
            return process_information;
        }
    }

    return NULL;
}

__attribute__((unused))
struct ohy_process* get_process_pid(const int id)
{
    struct task_struct *task;
    struct ohy_process* process_information;

    for_each_process(task)
    {
        if (task->pid == id)
        {
            memset(process_information->process_name, 0, sizeof(task->comm));
            process_information->pid = task->pid;
            return process_information;
        }
    }

    return process_information;
}

__attribute__((unused))
struct task_struct* get_task_by_pid(const char* name)
{
    struct task_struct *task_child;
    struct task_struct *t;
    struct list_head *l;
    
    struct task_struct* proc_struct;

    for_each_process(t)
    {
        if (strstr(t->comm, "main"))
        {
            list_for_each(l, &t->children)
            {
                task_child = list_entry(l, struct task_struct, sibling);

                if (strstr(task_child->comm, name)) {
                    proc_struct = pid_task(find_vpid(task_child->pid), PIDTYPE_PID);
                    return proc_struct;
                }
            }

            break;
        }
    }

    return NULL;
}

__attribute__((unused))
struct ohy_threads* get_threads_pid(const struct task_struct* proc)
{
    struct ohy_threads* threads = kzalloc(100 * sizeof(struct ohy_threads), GFP_KERNEL);
    struct task_struct* proc_thread;
    int t_count = 0;
    
    for_each_thread(proc, proc_thread)
    {
        threads[t_count].thread_id = proc_thread->pid;
        
        if (proc_thread->comm != NULL)
            strncpy(threads[t_count].thread_name, proc_thread->comm, sizeof(proc_thread->comm));

        t_count += 1;
    }

    return threads;
}

__attribute__((unused))
void cleanup(void)
{
    memset(current_proc, 0, sizeof(struct ohy_process));
}

#endif