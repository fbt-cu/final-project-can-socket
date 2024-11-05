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
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "aesdchar.h"
#include "aesd_ioctl.h"


//#include <linux/stdbool.h>
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Induja Narayanan"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

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

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                  loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld", count, *f_pos);
    
    // Validate input
    if (!filp || !buf || !f_pos || *f_pos < 0) {
        PDEBUG("Improper arguments");
        return -EINVAL;
    }

    struct aesd_dev *dev = filp->private_data;
    size_t offset = 0;
    size_t remaining_bytes = 0;

    // Lock
    retval = mutex_lock_interruptible(&dev->buffer_lock);
    if (retval != 0) {
        PDEBUG("Error: Unable to acquire mutex");
        return -ERESTART;
    }

    struct aesd_buffer_entry *temp = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &offset);
    if (!temp) {
        PDEBUG("Error: Entry for given position not found");
        retval = 0;
        goto unlock;
    }

    remaining_bytes = temp->size - offset;
    if (remaining_bytes > count) {
        remaining_bytes = count; // Prevent overflow
    }

    retval = copy_to_user(buf, temp->buffptr + offset, remaining_bytes);
    if (retval != 0) {
        remaining_bytes -= retval; // Adjust remaining bytes
        PDEBUG("Error: Copying data to user space failed");
        retval = -EFAULT;
        goto unlock;
    }

    *f_pos += remaining_bytes; // Update position
    retval = remaining_bytes; // Successfully read this many bytes

unlock:
    mutex_unlock(&dev->buffer_lock);
    PDEBUG("Mutex unlocked");
    return retval;
}

loff_t aesd_llseek(struct file *filp,loff_t offset,int whence)
{
    loff_t ret_value;
    int total_length = 0;
    struct aesd_dev *dev = filp->private_data;
    
    switch(whence)
    {
        case SEEK_SET:
            ret_value = filp->f_pos;
            break;
        case SEEK_CUR:
            ret_value = filp->f_pos +offset;
            break;
        case SEEK_END:
            ret_value = mutex_lock_interruptible(&dev->buffer_lock);
            if(ret_value !=0)
            {
                ret_value = -ERESTART;
                PDEBUG("Error: Unable to do mutex lock");
                goto exit;
            }
            for(int i= dev->buffer.out_offs; i!=dev->buffer.in_offs;)
            {
                total_length +=dev->buffer.entry[i].size;
                i = (i+1)%AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
            }
            mutex_unlock(&dev->buffer_lock);
            ret_value = total_length-1+offset;
            break;
        default:
            ret_value = -EINVAL;
            goto exit;           
    }
    if(ret_value<0 )
    {
        ret_value = -EINVAL;
        goto exit;
    }

   
    filp->f_pos = ret_value;
    PDEBUG("File position seeked to %d",filp->f_pos);

exit:
    return ret_value;
}


long aesd_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) 
{
     struct aesd_dev *dev = filp->private_data;
    long ret_value = 0;
    struct aesd_seekto seek_params;
    int total_length = 0;
    PDEBUG("Inside aesd_unlocked_ioctl");
    if (cmd != AESDCHAR_IOCSEEKTO)
    {
        PDEBUG("Error: aesd_unlocked_ioctl Invalid inputs\n");
        ret_value = -ENOTTY;
        goto exit;

    }

    if (copy_from_user(&seek_params, (struct aesd_seekto __user *)arg, sizeof(seek_params)))
    {
        PDEBUG("Error: Copying from user failed\n");
        ret_value = -EFAULT;
        goto exit;
    }
    if(seek_params.write_cmd > AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
    {
        PDEBUG("Error: Invalid command index offset\n");
        ret_value = -EINVAL;
        goto exit; 
    }

    seek_params.write_cmd = (seek_params.write_cmd+dev->buffer.out_offs)% AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    PDEBUG("Write cmd is %d, write cmd offset is %d\n",seek_params.write_cmd,seek_params.write_cmd_offset);
    if(seek_params.write_cmd_offset > dev->buffer.entry[seek_params.write_cmd].size)
    {
        PDEBUG("Error: Invalid command command offset\n");
        ret_value = -EINVAL;
        goto exit; 
    }
    ret_value = mutex_lock_interruptible(&dev->buffer_lock);
    if(ret_value !=0)
    {
        PDEBUG("Error: Unable to acquire mutex lock\n");
        ret_value = -ERESTART;
        goto exit;
    }

    for(int i=dev->buffer.out_offs;i!=seek_params.write_cmd;)
    {
        total_length+=dev->buffer.entry[i].size;
        i = (i+1)%AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    filp->f_pos = total_length + seek_params.write_cmd_offset;
    mutex_unlock(&dev->buffer_lock);
    PDEBUG("Total size is %d",total_length);
    PDEBUG("File position seeked to %d",filp->f_pos);
exit:
    return ret_value;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
    ssize_t retval = -ENOMEM;
    char *ptr_data_from_user_space = NULL;
    const char *newline_ptr = NULL;
    size_t size_until_new_linechar = 0;
    struct aesd_dev *dev = NULL;
    
    if (filp == NULL || buf == NULL || count <= 0 || f_pos == NULL || *f_pos < 0) {
        PDEBUG("Error: Invalid inputs\n");
        return -EINVAL;
    }

    dev = filp->private_data;
    if (dev == NULL) {
        PDEBUG("Invalid device pointer\n");
        return -EINVAL;
    }

    ptr_data_from_user_space = kmalloc(count, GFP_KERNEL);
    if (ptr_data_from_user_space == NULL) {
        PDEBUG("Error: Memory allocation failed in kernel\n");
        return -ENOMEM;
    }

    retval = copy_from_user(ptr_data_from_user_space, buf, count);
    if (retval) {
        PDEBUG("Error: Copy from user space failed in kernel\n");
        retval = -EFAULT;
        goto free_and_exit;
    }

    newline_ptr = memchr(ptr_data_from_user_space, '\n', count);
    size_until_new_linechar = newline_ptr ? newline_ptr - ptr_data_from_user_space + 1 : 0;

    retval = mutex_lock_interruptible(&dev->buffer_lock);
    if (retval != 0) {
        retval = -ERESTART;
        PDEBUG("Error: Acquiring lock failed\n");
        goto free_and_exit;
    }

    if (size_until_new_linechar > 0) {
        dev->entry.buffptr = krealloc(dev->entry.buffptr, dev->entry.size + size_until_new_linechar, GFP_KERNEL);
        if (dev->entry.buffptr == NULL) {
            PDEBUG("Error: Reallocation failed\n");
            retval = -ENOMEM;
            goto free_unlock_exit;
        }

        memcpy(dev->entry.buffptr + dev->entry.size, ptr_data_from_user_space, size_until_new_linechar);
        dev->entry.size += size_until_new_linechar;

        const char *ret_ptr = aesd_circular_buffer_add_entry(&dev->buffer, &dev->entry);
        if (ret_ptr) {
            kfree(ret_ptr);
        }

        dev->entry.size = 0;
        dev->entry.buffptr = NULL;
    } else {
        dev->entry.buffptr = krealloc(dev->entry.buffptr, dev->entry.size + count, GFP_KERNEL);
        if (dev->entry.buffptr == NULL) {
            PDEBUG("Error: Reallocation failed\n");
            retval = -ENOMEM;
            goto free_unlock_exit;
        }
        memcpy(dev->entry.buffptr + dev->entry.size, ptr_data_from_user_space, count);
        dev->entry.size += count;
    }

    retval = count;

free_unlock_exit:
    mutex_unlock(&dev->buffer_lock);
free_and_exit:
    kfree(ptr_data_from_user_space);
    return retval;
}


struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek = aesd_llseek,
    .unlocked_ioctl = aesd_unlocked_ioctl,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Adding as a char dev failed with error %d\n", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));
	aesd_circular_buffer_init(&aesd_device.buffer);
	mutex_init(&aesd_device.buffer_lock);


    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);
struct aesd_buffer_entry *entry;
uint8_t index = 0;
AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index){
if(entry->buffptr != NULL){
	kfree(entry->buffptr);
}
}

mutex_destroy(&aesd_device.buffer_lock);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
