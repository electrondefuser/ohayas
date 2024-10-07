#ifndef _OHY_COMDRIVER_H
#define _OHY_COMDRIVER_H

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>

#define COM_NAME "ohayaschdev"

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

static int dev_op(struct inode *inodep, struct file *filep) {
    return 0;
}

static int dev_rl(struct inode *inodep, struct file *filep) {
    return 0;
}

static ssize_t dev_rd(struct file *filep, char __user *user_buffer, size_t len, loff_t *offset) {
    return 0;
}

static ssize_t dev_wr(struct file *filep, char __user *user_buffer, size_t len, loff_t *offset) {
    return 0;
}

#endif