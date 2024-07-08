#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>

int main() {
    pid_t child;
    long orig_data, data;
    struct user_regs_struct regs;

    child = fork();

    if (child == 0) {
        // 子进程

        // 使用 ptrace 跟踪自己
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        // 执行需要调试的程序
        execl("./noF_debug", "noF_debug", NULL);
    } else {
        // 父进程

        // 等待子进程停止
        wait(NULL);

        // 使用 ptrace 跟踪子进程
        // ptrace(PTRACE_ATTACH, child, NULL, NULL);

        // 等待子进程的状态变为停止状态
        // wait(NULL);

        // 获取子进程的寄存器状态
        ptrace(PTRACE_GETREGS, child, NULL, &regs);

        // 设置断点位置为 main 函数的地址
        long breakpoint_addr = (long)main;
        printf("Address of main:%lx\n",(long)main);
        // 保存原始指令数据
        orig_data = ptrace(PTRACE_PEEKTEXT, child, (void *)breakpoint_addr, NULL);

        // 设置断点指令
        data = (orig_data & ~0xFF) | 0xCC;
        ptrace(PTRACE_POKETEXT, child, (void *)breakpoint_addr, (void *)data);

        // 恢复子进程运行
        ptrace(PTRACE_CONT, child, NULL, NULL);

        // 等待子进程再次停止，表示断点触发
        wait(NULL);
        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        // 输出断点触发位置
        printf("Breakpoint hit at address: %llx\n", regs.rip);

        // 恢复原始指令
        ptrace(PTRACE_POKETEXT, child, (void *)breakpoint_addr, (void *)orig_data);

        // 恢复子进程运行
        ptrace(PTRACE_CONT, child, NULL, NULL);

        // 等待子进程结束
        wait(NULL);
    }

    return 0;
}
