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
    long data;
    struct user_regs_struct regs;
    child = fork();
    
    if (child == 0) {
        // 子进程
        printf("Child start.\n");
        sleep(2);
        // void* handle = dlopen(NULL, RTLD_LAZY); // 获取动态链接器句柄
        // void* dlopen_addr = dlsym(handle, "dlopen"); // 获取dlopen函数地址
        // printf("Address of dlopen = %p;\n",dlopen_addr);
        // // 使用dlopen_addr进行后续操作...

        // const char *libraryPath = "./lib4.so";  // 替换为你要加载的库文件路径

        // // 将地址转换为函数指针类型
        // void* (*dlopenFunc)(const char *, int) = (void* (*)(const char *, int))dlopen_addr;

        // // 调用 dlopen 函数
        // void *handle1 = dlopenFunc(libraryPath, RTLD_LAZY);
        // if (handle == NULL) {
        //     fprintf(stderr, "Failed to load library: %s\n", dlerror());
        //     return 1;
        // }
        // // 成功加载库文件，可以进行后续操作

        // // 关闭库文件
        // dlclose(handle1);
        printf("Child end.\n");
        // execl("./test4","test4",NULL);
         void* handle = dlopen(NULL, RTLD_LAZY); // 获取动态链接器句柄
        void* dlopen_addr = dlsym(handle, "dlopen"); // 获取dlopen函数地址
        printf("Address of dlopen in child = %p;\n",dlopen_addr);
        // execl("./test4","test4",0);
    } else {
        // 父进程
        printf("Parent start.\n");
        int attach_result = ptrace(PTRACE_ATTACH, child, NULL, NULL);
        if (attach_result == -1) {
            printf("附加失败，错误号：%d\n", errno);
            return 1;
        }
        printf("成功附加到子进程\n");
        wait(NULL);


        void* handle = dlopen(NULL, RTLD_LAZY); // 获取动态链接器句柄
        void* dlopen_addr = dlsym(handle, "dlopen"); // 获取dlopen函数地址
        printf("Address of dlopen in father = %p;\n",dlopen_addr);
        // 使用dlopen_addr进行后续操作...

        const char *libraryPath = "./lib4.so";  // 替换为你要加载的库文件路径

        // 将地址转换为函数指针类型
        void* (*dlopenFunc)(const char *, int) = (void* (*)(const char *, int))dlopen_addr;

        // 调用 dlopen 函数
        void *handle1 = dlopenFunc(libraryPath, RTLD_LAZY);
        if (handle == NULL) {
            fprintf(stderr, "Failed to load library: %s\n", dlerror());
            return 1;
        }

        // 成功加载库文件，可以进行后续操作

        // 关闭库文件
        dlclose(handle1);

        ptrace(PTRACE_CONT, child, NULL, NULL);
        wait(NULL);
        ptrace(PTRACE_DETACH, child, NULL, NULL);
        printf("Parent end.\n");
    }

    
    return 0;
}
