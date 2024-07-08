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
        lib_handle = dlopen("/home/cyn/Desktop/DA/summer/ptrace_test/lib1.so", RTLD_LAZY);
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

        // 在子进程中调用函数
        ptrace(PTRACE_ATTACH, child, NULL, NULL);
        sleep(2);
        // wait(NULL);
        ptrace(PTRACE_CONT, child, NULL, NULL);
        wait(NULL);
        ptrace(PTRACE_DETACH, child, NULL, NULL);

        // 关闭共享库
        dlclose(lib_handle);

        printf("Child process has exited.\n");
    }

    return 0;
}
