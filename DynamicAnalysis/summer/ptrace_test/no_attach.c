#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include<dlfcn.h>
#include<sys/user.h>

int main() {

    void *handle;
    int (*foo)(int, int);
    char *error;

    pid_t child_pid = fork();
    struct user_regs_struct regs;
    if (child_pid == 0) {
        // 子进程中运行 noF_debug 程序
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("./noF_debug", "noF_debug", NULL);
        exit(0);
    } else{
        // 等待子进程停止
        waitpid(child_pid, NULL, 0);

        handle = dlopen("/home/cyn/Desktop/DA/summer/ptrace_test/lib1.so", RTLD_LAZY);
        if (!handle) {
            fprintf(stderr, "%s\n", dlerror());
            return 1;
        }
        dlerror(); // 清除错误

        foo = dlsym(handle, "foo");
        error = dlerror();
        if (error != NULL) {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return 1;
        }

        printf("Address of 'foo' function: %p\n", (void*)foo);


        ptrace(PTRACE_GETREGS, child_pid ,NULL, &regs);

        long ins = ptrace(PTRACE_PEEKTEXT, child_pid , regs.rip, NULL);
        printf("RIP: %llx Instruction executed: %lx\n",regs.rip, ins);

        

        
        // // 修改地址 0x555555557fc8 处的内容
        // long data = 0x7ffff7fc5147;
        // ptrace(PTRACE_POKEDATA, child_pid, (void*)0x555555557fc8, (void*)data);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    }

    return 0;
}
