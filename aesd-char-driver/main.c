/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#include "aesd-circular-buffer.h"
#include "aesdchar.h"

int aesd_major = 0; // use dynamic major
int aesd_minor = 0;

MODULE_AUTHOR("Fernando Becerra");
MODULE_LICENSE("Dual BSD/GPL");

int aesd_open(struct inode *inode, struct file *filp);
int aesd_release(struct inode *inode, struct file *filp);
ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);
ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos);
static const char *find_newline(const char *buffer, size_t buffer_size);
loff_t aesd_llseek(struct file *fp, loff_t offset, int pos);
int aesd_fsync(struct file *fp, loff_t unused1, loff_t unused2, int datasync);
static int aesd_setup_cdev(struct aesd_dev *dev);
int aesd_init_module(void);
void aesd_cleanup_module(void);

struct aesd_dev aesd_device;

struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
    .open = aesd_open,
    .release = aesd_release,
    .llseek = aesd_llseek,
    .fsync = aesd_fsync};

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    filp->private_data = NULL;
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    ssize_t errno = 0;
    struct aesd_dev *device = filp->private_data;
    struct aesd_buffer_entry *entry = NULL;
    size_t entry_offset;
    size_t available_bytes;

    if (mutex_lock_interruptible(&device->buffer_mutex))
    {
        return -EINTR;
    }

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&device->buffer, *f_pos, &entry_offset);
    if (!entry)
    {
        mutex_unlock(&device->buffer_mutex);
        return 0;
    }

    available_bytes = entry->size - entry_offset;
    if (count > available_bytes)
    {
        count = available_bytes;
    }

    if (copy_to_user(buf, entry->buffptr + entry_offset, count) != 0)
    {
        errno = -EFAULT;
        mutex_unlock(&device->buffer_mutex);
        return errno;
    }

    *f_pos += count;
    errno = count;

    mutex_unlock(&device->buffer_mutex);
    return errno;
}

static const char *find_newline(const char *buffer, size_t buffer_size)
{
    size_t i;

    for (i = 0; i < buffer_size; i++)
    {
        if (buffer[i] == '\n')
        {
            return &buffer[i];
        }
    }
    return NULL;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    ssize_t errno = -ENOMEM;
    char *str_buf = NULL;
    const char *eol_ptr = NULL;
    struct aesd_buffer_entry new_entry;
    struct aesd_dev *device;

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

    device = (struct aesd_dev *)(filp->private_data);
    if (!buf || count == 0)
    {
        return -EINVAL;
    }

    str_buf = kmalloc(count, GFP_KERNEL);
    if (!str_buf)
    {
        return -ENOMEM;
    }

    if (copy_from_user(str_buf, buf, count) != 0)
    {
        kfree(str_buf);
        return -EFAULT;
    }

    if (mutex_lock_interruptible(&device->next_line_mtx) != 0)
    {
        kfree(str_buf);
        return -EINTR;
    }

    eol_ptr = find_newline(str_buf, count);
    if (eol_ptr != NULL)
    {
        count = eol_ptr - str_buf + 1;
    }

    if (device->next_line != NULL)
    {
        char *ptr = krealloc(device->next_line, device->next_line_size + count, GFP_KERNEL);
        if (ptr == NULL)
        {
            mutex_unlock(&device->next_line_mtx);
            kfree(str_buf);
            return -ENOMEM;
        }
        device->next_line = ptr;
        memcpy(device->next_line + device->next_line_size, str_buf, count);
        device->next_line_size += count;
        kfree(str_buf);
    }
    else
    {
        device->next_line = str_buf;
        device->next_line_size = count;
    }

    errno = count;
    *f_pos += count;

    if (eol_ptr != NULL)
    {
        if (mutex_lock_interruptible(&device->buffer_mutex) != 0)
        {
            mutex_unlock(&device->next_line_mtx);
            return -EINTR;
        }

        new_entry.buffptr = device->next_line;
        new_entry.size = device->next_line_size;
        aesd_circular_buffer_add_entry(&device->buffer, &new_entry);

        mutex_unlock(&device->buffer_mutex);

        device->next_line = NULL;
        device->next_line_size = 0;
    }

    mutex_unlock(&device->next_line_mtx);
    return errno;
}

loff_t aesd_llseek(struct file *fp, loff_t offset, int pos)
{
    struct aesd_dev *device = (struct aesd_dev *)(fp->private_data);
    loff_t new_pos;
    loff_t fileSize = 0;
    struct aesd_buffer_entry *entryptr;
    int i;

    if (mutex_lock_interruptible(&device->buffer_mutex) != 0)
    {
        return -EINTR;
    }

    AESD_CIRCULAR_BUFFER_FOREACH(entryptr, &device->buffer, i)
    {
        fileSize += entryptr->size;
    }

    mutex_unlock(&device->buffer_mutex);

    switch (pos)
    {
    case SEEK_SET:
        new_pos = offset;
        break;
    case SEEK_CUR:
        new_pos = fp->f_pos + offset;
        break;
    case SEEK_END:
        new_pos = fileSize + offset;
        break;
    default:
        return -EINVAL;
    }

    if (new_pos < 0)
    {
        new_pos = 0;
    }
    else if (new_pos > fileSize)
    {
        new_pos = fileSize;
    }

    fp->f_pos = new_pos;
    return new_pos;
}

int aesd_fsync(struct file *fp, loff_t unused1, loff_t unused2, int datasync)
{
    return 0;
}

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err)
    {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0)
    {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device, 0, sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    mutex_init(&aesd_device.buffer_mutex);
    mutex_init(&aesd_device.next_line_mtx); // Initialize the next line mutex
    aesd_circular_buffer_init(&aesd_device.buffer);

    result = aesd_setup_cdev(&aesd_device);

    if (result)
    {
        unregister_chrdev_region(dev, 1);
    }
    return result;
}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    if (aesd_device.next_line) // Check for NULL before freeing
    {
        kfree(aesd_device.next_line);
    }

    int i;
    for (i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++)
    {
        struct aesd_buffer_entry null_entry = {.buffptr = NULL, .size = 0};
        aesd_circular_buffer_add_entry(&aesd_device.buffer, &null_entry);
    }

    mutex_destroy(&aesd_device.buffer_mutex);
    mutex_destroy(&aesd_device.next_line_mtx);

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);