// ftrace_helper.c
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/printk.h>
#include "ftrace_helper.h"

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = (unsigned long)kallsyms_lookup_name(hook->name);
    if (!hook->address) {
        printk(KERN_ERR "ftrace_helper: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }
    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                   struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err;
    size_t i;

    for (i = 0; i < count; i++) {
        struct ftrace_hook *hook = &hooks[i];
        
        err = fh_resolve_hook_address(hook);
        if (err)
            goto error;
        
        hook->ops.func = fh_ftrace_thunk;
        hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE | FTRACE_OPS_FL_IPMODIFY;
        
        err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
        if (err) {
            printk(KERN_ERR "ftrace_helper: ftrace_set_filter_ip failed: %d\n", err);
            goto error;
        }
        
        err = register_ftrace_function(&hook->ops);
        if (err) {
            printk(KERN_ERR "ftrace_helper: register_ftrace_function failed: %d\n", err);
            ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
            goto error;
        }
    }
    return 0;

error:
    while (i != 0) {
        hook = &hooks[--i];
        unregister_ftrace_function(&hook->ops);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    }
    return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        struct ftrace_hook *hook = &hooks[i];
        unregister_ftrace_function(&hook->ops);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    }
}