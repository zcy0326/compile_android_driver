#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/hw_breakpoint.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/sched/signal.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>
#include <linux/sched/task.h>
#include <linux/rculist.h>  // 新增：RCU相关头文件

// 模块参数：目标包名、SO库名和偏移量
static char *target_package = NULL;
static char *target_so = NULL;
static unsigned long so_offset = 0;

// 全局变量
static pid_t target_pid = 0;
static unsigned long target_addr = 0;
static struct perf_event *bp_event = NULL;
static struct task_struct *monitor_thread = NULL;
static bool breakpoint_active = false;

/**
 * 从包名获取主进程PID（修复task->parent安全访问和kernel_read返回值处理）
 */
static pid_t get_pid_by_package(const char *package)
{
    struct task_struct *task;
    char comm[256];
    int len;
    struct file *file;
    char buf[1024];
    ssize_t ret;
    struct task_struct *parent;  // 用于安全访问父进程

    rcu_read_lock();
    for_each_process(task) {
        // 构建cmdline路径
        len = snprintf(comm, sizeof(comm), "/proc/%d/cmdline", task->pid);
        if (len <= 0 || len >= sizeof(comm))
            continue;

        // 打开文件（检查是否成功）
        file = filp_open(comm, O_RDONLY, 0);
        if (IS_ERR(file))
            continue;

        // 读取文件内容（完整处理返回值）
        memset(buf, 0, sizeof(buf));
        ret = kernel_read(file, buf, sizeof(buf)-1, &file->f_pos);
        filp_close(file, NULL);  // 确保文件关闭

        // 处理读取失败或空内容的情况
        if (ret <= 0)
            continue;

        // 检查包名匹配
        if (strstr(buf, package)) {
            // 安全访问父进程（RCU保护）
            parent = rcu_dereference(task->parent);
            if (parent && parent->pid == 1) {  // 父进程为init（PID=1）
                rcu_read_unlock();
                return task->pid;
            }
        }
    }
    rcu_read_unlock();
    return 0;
}

/**
 * 等待目标进程启动
 */
static int wait_for_process(const char *package)
{
    printk(KERN_INFO "等待进程 %s 启动...\n", package);
    
    while (!kthread_should_stop()) {
        target_pid = get_pid_by_package(package);
        if (target_pid != 0) {
            printk(KERN_INFO "进程 %s 已启动，主进程PID: %d\n", package, target_pid);
            return 0;
        }
        msleep(1000);
    }
    
    return -1;
}

/**
 * 通过SO库名和偏移量计算实际地址（修复kernel_read返回值处理）
 */
static unsigned long get_address_by_so_offset(pid_t pid, const char *so_name, unsigned long offset)
{
    char maps_path[256];
    struct file *file;
    char buf[1024];
    ssize_t ret;
    unsigned long start_addr = 0;
    loff_t pos = 0;

    // 构建maps路径
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    file = filp_open(maps_path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "无法打开 %s: %ld\n", maps_path, PTR_ERR(file));
        return 0;
    }

    // 读取并解析maps内容（完整处理返回值）
    memset(buf, 0, sizeof(buf));
    while ((ret = kernel_read(file, buf, sizeof(buf)-1, &pos)) > 0) {
        buf[ret] = '\0';
        if (strstr(buf, so_name)) {
            if (sscanf(buf, "%lx-", &start_addr) == 1) {
                printk(KERN_INFO "找到 %s 加载地址: 0x%lx\n", so_name, start_addr);
                break;
            }
        }
        // 处理长行（未读完的情况）
        if (ret == sizeof(buf)-1 && buf[sizeof(buf)-2] != '\n') {
            while (pos < file->f_inode->i_size && buf[ret-1] != '\n') {
                ret = kernel_read(file, buf, 1, &pos);
                if (ret <= 0) break;  // 处理读取失败
            }
        }
        memset(buf, 0, sizeof(buf));
    }

    filp_close(file, NULL);  // 确保文件关闭
    return start_addr ? (start_addr + offset) : 0;
}

/**
 * 硬件断点触发回调函数
 */
static void hw_breakpoint_handler(struct perf_event *bp,
                                 struct perf_sample_data *data,
                                 struct pt_regs *regs)
{
    unsigned long original_pc;

    // 验证目标进程和断点状态
    if (current->pid != target_pid || !breakpoint_active)
        return;

    // 跳过当前指令（ARM64指令通常4字节）
    original_pc = regs->pc;
    regs->pc = original_pc + 4;
    
    // 修改W21寄存器（X21低32位）为1
    regs->regs[21] = (regs->regs[21] & 0xFFFFFFFF00000000) | 0x1;
    
    printk(KERN_INFO "已跳过指令: 0x%lx -> 0x%lx, W21已设置为1\n",
           original_pc, regs->pc);
}

/**
 * 设置硬件断点
 */
static int setup_hw_breakpoint(void)
{
    struct perf_event_attr attr;
    struct task_struct *target_task;

    // 释放已有断点
    if (bp_event) {
        perf_event_release_kernel(bp_event);
        bp_event = NULL;
    }

    // 获取目标进程结构体（带有效性检查）
    target_task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
    if (!target_task) {
        printk(KERN_ERR "无法获取进程结构体（PID: %d）\n", target_pid);
        return -EINVAL;
    }

    // 初始化断点属性（安卓5.10兼容）
    hw_breakpoint_init(&attr);
    attr.bp_addr = target_addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_X;  // 执行触发（5.10内核宏）
    attr.disabled = 0;

    // 创建硬件断点
    bp_event = perf_event_create_kernel_counter(&attr,
                                         0,
                                         target_task,
                                         hw_breakpoint_handler,
                                         NULL);

    if (IS_ERR(bp_event)) {
        printk(KERN_ERR "创建硬件断点失败，错误码: %ld\n", PTR_ERR(bp_event));
        bp_event = NULL;
        return PTR_ERR(bp_event);
    }

    breakpoint_active = true;
    printk(KERN_INFO "已在地址 0x%lx 设置硬件断点 (PID: %d)\n",
           target_addr, target_pid);
    return 0;
}

/**
 * 重新检查并更新断点
 */
static void refresh_breakpoint_if_needed(void)
{
    pid_t current_pid;

    current_pid = get_pid_by_package(target_package);
    
    // 处理进程退出或重启
    if (current_pid == 0 || current_pid != target_pid) {
        printk(KERN_INFO "目标进程已退出或重启，重新等待...\n");
        breakpoint_active = false;
        
        if (wait_for_process(target_package) != 0)
            return;
            
        target_addr = get_address_by_so_offset(target_pid, target_so, so_offset);
        if (target_addr != 0) {
            setup_hw_breakpoint();
        } else {
            printk(KERN_ERR "无法获取目标地址，重试中...\n");
        }
    }
}

/**
 * 内核线程：监控进程状态
 */
static int monitor_process(void *data)
{
    // 等待目标进程启动
    if (wait_for_process(target_package) != 0) {
        printk(KERN_ERR "监控线程终止\n");
        return -1;
    }

    // 获取目标地址
    target_addr = get_address_by_so_offset(target_pid, target_so, so_offset);
    if (target_addr == 0) {
        printk(KERN_ERR "无法获取目标地址，模块无法正常工作\n");
        return -1;
    }

    // 设置硬件断点
    if (setup_hw_breakpoint() != 0) {
        printk(KERN_ERR "无法设置硬件断点，模块无法正常工作\n");
        return -1;
    }

    // 持续监控
    while (!kthread_should_stop()) {
        refresh_breakpoint_if_needed();
        msleep(5000);
    }

    // 清理资源
    breakpoint_active = false;
    if (bp_event) {
        perf_event_release_kernel(bp_event);
        bp_event = NULL;
    }

    printk(KERN_INFO "监控线程退出\n");
    return 0;
}

/**
 * 模块初始化
 */
static int __init hw_breakpoint_init_module(void)
{
    // 检查参数有效性
    if (!target_package || !target_so || so_offset == 0) {
        printk(KERN_ERR "请设置目标包名、SO库名和偏移量\n");
        printk(KERN_ERR "示例: insmod hw_breakpoint.ko target_package=com.example.app target_so=libexample.so so_offset=0x12345\n");
        return -EINVAL;
    }

    // 创建监控线程
    monitor_thread = kthread_run(monitor_process, NULL, "hw_break_monitor");
    if (IS_ERR(monitor_thread)) {
        printk(KERN_ERR "创建监控线程失败: %ld\n", PTR_ERR(monitor_thread));
        return PTR_ERR(monitor_thread);
    }

    printk(KERN_INFO "硬件断点模块加载成功\n");
    return 0;
}

/**
 * 模块退出
 */
static void __exit hw_breakpoint_exit_module(void)
{
    // 停止监控线程
    if (monitor_thread) {
        kthread_stop(monitor_thread);
        monitor_thread = NULL;
    }

    // 释放断点资源
    breakpoint_active = false;
    if (bp_event) {
        perf_event_release_kernel(bp_event);
        bp_event = NULL;
    }

    printk(KERN_INFO "硬件断点模块卸载成功\n");
}

// 模块参数定义
module_param(target_package, charp, 0644);
module_param(target_so, charp, 0644);
module_param(so_offset, ulong, 0644);
MODULE_PARM_DESC(target_package, "目标应用包名（例如：com.example.target）");
MODULE_PARM_DESC(target_so, "目标SO库文件名（例如：libtarget.so）");
MODULE_PARM_DESC(so_offset, "SO库中的偏移地址（十六进制）");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("安卓5.10内核硬件断点模块（跳过指令并修改W21）");

module_init(hw_breakpoint_init_module);
module_exit(hw_breakpoint_exit_module);
