#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include<dlfcn.h>
#include<sys/user.h>
#include <sys/mman.h>

void print_bytes(unsigned long data) {
    for (int i = 0; i < sizeof(unsigned long); i++) {
        unsigned char byte = (data >> (i * 8)) & 0xff;
        printf("%02x ", byte);
    }
    printf("\n");
}

int main() {
    pid_t child;
    child = fork();
    if (child == 0) {
        // 子进程
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        printf("Child process start.\n");
        execl("./noF_debug", "noF_debug", NULL);
    } else {
        // 父进程
        printf("Parent process start.\n");
        wait(NULL);
        // if (ptrace(PTRACE_ATTACH, child, NULL, NULL) == -1) {
        //     perror("ptrace attach");
        //     return 1;
        // }
        // 继续执行子进程
        
        printf("Parent process is running.\n");
        ptrace(PTRACE_CONT, child, NULL, NULL);
        wait(NULL);
        printf("Parent process end.\n");
    }

    
    return 0;
}
