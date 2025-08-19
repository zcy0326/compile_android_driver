// ftrace_helper.h
#ifndef FTRACE_HELPER_H
#define FTRACE_HELPER_H

#include <linux/ftrace.h>

#define HOOK(_name, _hook, _orig) \
    { \
        .name = (_name), \
        .function = (_hook), \
        .original = (_orig), \
    }

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
};

int fh_install_hooks(struct ftrace_hook *hooks, size_t count);
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);

#endif