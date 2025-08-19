// ftrace_helper.h
#include <linux/ftrace.h>

#define HOOK(_name, _hook, _orig) \
    { \
        .name = (_name), \
        .function = (_hook), \
        .original = (_orig), \
    }

struct ftrace_hook {
    const char *name;     // 要挂钩的函数名（如 "__x64_sys_ioctl"）
    void *function;       // 替换函数（如 hooked_ioctl）
    void *original;       // 保存原函数指针
};

// 安装钩子
int fh_install_hooks(struct ftrace_hook *hooks, size_t count);

// 移除钩子
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);