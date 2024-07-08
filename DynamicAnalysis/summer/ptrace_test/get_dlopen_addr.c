#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
int main() {
    pid_t child;
    child = fork();
    if (child == 0) {
        // 子进程
        printf("Child start.\n");
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("./victim", "victim", NULL);
    } else {
        // 父进程
        printf("Parent start.\n");

        wait(NULL);
        struct user_regs_struct regs_origin;
	    struct user_regs_struct regs_change;


        void* handle = dlopen(NULL, RTLD_LAZY); // 获取动态链接器句柄
        void* dlopen_addr = dlsym(handle, "dlopen"); // 获取dlopen函数地址
        printf("Address of dlopen = %p;",dlopen_addr);
        // 使用dlopen_addr进行后续操作...

        regs_change.rax = dlopen_addr; // dlopen函数的地址
        regs_change.rdi = (unsigned long)"./lib4.so"; // 要加载的库路径
        regs_change.rsi = 0; // 标志参数，这里使用0
        ptrace(PTRACE_SETREGS, 0, NULL, &regs_change);

        //注入call dlopen的代码
        ptrace(PTRACE_CONT, 0, NULL, NULL);
        wait(NULL);
        dlclose(handle); // 关闭动态链接器句柄
    }
    return 0;
}
