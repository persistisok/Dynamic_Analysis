#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <dlfcn.h>

int main() {
    pid_t child;
    void* lib_handle;
    void (*func)();
    struct user_regs_struct regs;

    child = fork();
    if (child == 0) {
        // 子进程
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("./noF_debug", "noF_debug", NULL);
    } else {
        // 父进程
        wait(NULL);
        printf("Child process has been started.\n");

        // 加载共享库
        lib_handle = dlopen("/home/cyn/Desktop/DA/summer/ptrace_test/lib4.so", RTLD_LAZY);
        if (lib_handle == NULL) {
            perror("Failed to load library");
            return 1;
        }

        // 获取函数地址
        func = dlsym(lib_handle, "foo");
        if (func == NULL) {
            perror("Failed to find function");
            return 1;
        }

        printf("Address of 'foo' function in father: %p\n", (void*)func);

        ptrace(PTRACE_ATTACH, child, NULL, NULL);
        sleep(1);
        // // wait(NULL);
        // printf("Child process has been attached.\n");

        // 获取共享库的路径
        // char lib_path[] = "/home/cyn/Desktop/DA/summer/ptrace_test/lib4.so";

        // 在子进程中重新加载共享库
        ptrace(PTRACE_GETREGS, child, 0, &regs);
        // regs.rdi = (unsigned long long)dlopen(lib_path, RTLD_NOW);
        // ptrace(PTRACE_SETREGS, child, 0, &regs);

        // 获取函数地址
        // void (*func)();
        // func = dlsym(dlopen(lib_path, RTLD_NOW), "foo");
        // if (func == NULL) {
        //     perror("Failed to find function");
        // return 1;
        // }

        // 设置寄存器的 rip 为函数地址
        // regs.rip = (unsigned long long)func;
        regs.rip++;
        ptrace(PTRACE_SETREGS, child, 0, &regs);
        // 继续执行子进程
        regs.rip--;
        ptrace(PTRACE_SETREGS, child, 0, &regs);
        
        ptrace(PTRACE_CONT, child, NULL, NULL);
        wait(NULL);
        ptrace(PTRACE_DETACH, child, NULL, NULL);
        printf("Child process has exited.\n");
    }

    return 0;
}