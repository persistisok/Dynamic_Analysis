#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include<dlfcn.h>
#include<sys/user.h>
int main() {
    pid_t child;
    
    child = fork();
    void* handle;
    if (child == 0) {
        // 子进程中
        // 使用 execve 启动要调试的程序
        char* argv[] = { "/bin/ls", NULL };
        char* envp[] = { NULL };
        
        // 在子进程中加载共享库并执行程序
        handle = dlopen("/home/cyn/Desktop/DA/summer/ptrace_test/lib4.so", RTLD_LAZY);
        if (handle == NULL) {
            fprintf(stderr, "Failed to open library: %s\n", dlerror());
            return 1;
        }
        
        // 获取共享库中的函数地址
        void (*func)() = dlsym(handle, "foo");
        if (func == NULL) {
            fprintf(stderr, "Failed to get function pointer: %s\n", dlerror());
            dlclose(handle);
            return 1;
        }
        
        // 调用共享库中的函数
        func();
        
        
        
        // 在子进程中执行要调试的程序
        if (execve("/bin/ls", argv, envp) == -1) {
            perror("Failed to execute program");
            return 1;
        }
    } else if (child > 0) {
        // 父进程中
        // 等待子进程结束
        waitpid(child, NULL, 0);
    } else {
        perror("Failed to fork");
        return 1;
    }
    return 0;
}
