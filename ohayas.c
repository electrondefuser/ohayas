#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/tracepoint.h>
#include <linux/kprobes.h>

#include "ohyutils.h"
#include "ohyprocess.h"
#include "arm64/ohyinterceptor.h"

#define OHY_CHR_DEVC_NAME "ohyc"
#define OHY_DEV_MAJOR_NUM 220
#define OHY_DEV_MINOR_NUM 0

static int dev_op(struct inode *, struct file *);
static int dev_rl(struct inode *, struct file *);

static ssize_t dev_rd(struct file *, char __user *, size_t, loff_t *);
static ssize_t dev_wr(struct file *, const char __user *, size_t, loff_t *);

struct file_operations fops = {
    .owner      = THIS_MODULE,
    .open       = dev_op,
    .read       = dev_rd,
    .write      = dev_wr,
    .release    = dev_rl,
};

static int major;

static char kernel_buffer[64];
static short kernel_buffer_len;
static short open_cnt;

static int int_arg = 0;

/* void scan_process(void)
{
    int i = 0;
    struct ohy_threads* threads_proc;
    struct task_struct* proc = get_task_by_pid("com.axis.mobile");

    if (proc != NULL)
    {
        threads_proc = get_threads_pid(proc);
        if (threads_proc != NULL)
        {
            for (i = 0; i < 100; i++)
                printk(KERN_ALERT "PROC_THREADS: %i: %s", threads_proc[i].thread_id, threads_proc[i].thread_name);


            printk(KERN_ALERT "PROC_THREADS_FRIDA: %i", get_frida_gadget_pid(threads_proc));
            kfree(threads_proc);
        }
    }
} */

static int dev_op(struct inode *inodep, struct file *filep)
{
    open_cnt++;
    printk(KERN_INFO "ohayas_engine: open (cnt: %d)\n", open_cnt);
    return 0;
}

static int dev_rl(struct inode *inodep, struct file *filep)
{
    printk(KERN_INFO "ohayas_engine: release\n");
    return 0;
}

static ssize_t dev_wr(struct file *filep, const char __user *user_buffer, size_t len, loff_t *offset)
{
    char kbuffer[64];

    if (copy_from_user(kbuffer, user_buffer, len) != 0)
    {
        printk(KERN_ALERT "ohayas_engine: write - failed to copy %zu chars from userspace \n", len);
        return -14;
    }

    kernel_buffer_len = len;
    printk(KERN_INFO "ohayas_engine: Received Command\n");

    hook_init();
    // scan_process();

    return len;
}

static ssize_t dev_rd(struct file *filep, char __user *user_buffer, size_t len, loff_t *offset)
{
    int errors = 0;
    int tmp_len = 0;

    printk(KERN_INFO "ohayas_engine: read\n");
    errors = copy_to_user(user_buffer, kernel_buffer, kernel_buffer_len);

    if (errors == 0)
    {
        printk(KERN_INFO "ohayas_engine: read - copied %d characters to userspace\n", kernel_buffer_len);
        tmp_len = kernel_buffer_len;
        kernel_buffer_len = 0;

        return tmp_len;
    }

    printk(KERN_ALERT "ohayas_engine: read - failed to copy %d characters to userspace\n", kernel_buffer_len);
    return -EFAULT;
}

static int  __init ohayas_init(void)
{
    printk(KERN_INFO "ohayas_engine: %s - int_arg : %d", __FUNCTION__, int_arg);
    major = register_chrdev(0, OHY_CHR_DEVC_NAME, &fops);

    if (major < 0) {
        printk(KERN_ALERT "ohayas_engine: init - major : %d (< 0)\n", major);
        return major;
    }

    printk(KERN_INFO "ohayas_engine: init - major : %d\n", major);
    return 0;
}

static void __exit ohayas_exit(void)
{
    unregister_chrdev(major, OHY_CHR_DEVC_NAME);
    printk(KERN_INFO "ohayas_engine: exit\n");
}

module_init(ohayas_init);
module_exit(ohayas_exit);

MODULE_DESCRIPTION("ohayas");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
MODULE_AUTHOR("electrondefuser<vineetnr1@gmail.com>");
