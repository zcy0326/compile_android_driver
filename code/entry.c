// entry.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/device.h>
#include "comm.h"
#include "memory.h"
#include "process.h"

#define OP_CMD_READ 601
#define OP_CMD_WRITE 602
#define OP_CMD_BASE 603

static char *hook_name = NULL;
static struct class *hook_class = NULL;
static struct device *hook_device = NULL;


static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_ioctl", hooked_ioctl, &orig_ioctl),
};

static asmlinkage long (*orig_ioctl)(unsigned int fd, unsigned int cmd, unsigned long arg);

static asmlinkage long hooked_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name[0x100] = {0};

    if (cmd >= OP_CMD_READ && cmd <= OP_CMD_BASE)
    {
        switch(cmd)
        {
            case OP_CMD_READ:
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm))) {
                    return -EFAULT;
                }
                if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
                    return -EIO;
                }
                break;
            case OP_CMD_WRITE:
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm))) {
                    return -EFAULT;
                }
                if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
                    return -EIO;
                }
                break;
            case OP_CMD_BASE:
                if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) || 
                    copy_from_user(name, (void __user*)mb.name, sizeof(name)-1)) {
                    return -EFAULT;
                }
                mb.base = get_module_base(mb.pid, name);
                if (copy_to_user((void __user*)arg, &mb, sizeof(mb))) {
                    return -EFAULT;
                }
                break;
            default:
                break;
        }
        return 0;
    }
    
    return orig_ioctl(fd, cmd, arg);
}

void hide_module(void)
{
    list_del_init(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    THIS_MODULE->sect_attrs = NULL;
    THIS_MODULE->notes_attrs = NULL;
    THIS_MODULE->num_symtab = 0;
    THIS_MODULE->symtab = NULL;
}

void cleanup_hook(void)
{
    if (hook_device) {
        device_destroy(hook_class, MKDEV(0, 0));
        hook_device = NULL;
    }
    if (hook_class) {
        class_destroy(hook_class);
        hook_class = NULL;
    }
    if (hook_name) {
        kfree(hook_name);
        hook_name = NULL;
    }
}

void show_qt_result(int success)
{
    if (success) {
        printk(KERN_INFO "qt独家hook刷入成功\n");
    } else {
        printk(KERN_ERR "qt独家hook刷入失败\n");
        mdelay(3000);
        kernel_restart(NULL);
    }
}

static int __init my_module_init(void)
{
    int ret = 0;
    
    
    hook_name = get_rand_str();
    if (!hook_name) {
        show_qt_result(0);
        return -ENOMEM;
    }
    
    
    ret = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (ret) {
        cleanup_hook();
        show_qt_result(0);
        return ret;
    }
    
    
    hide_module();
    
    printk(KERN_INFO "Hook module loaded.\n");
    show_qt_result(1);
    
    return 0;
}

static void __exit my_module_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    cleanup_hook();
    printk(KERN_INFO "Hook module unloaded.\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hook module using ftrace");
MODULE_AUTHOR("Your Name");