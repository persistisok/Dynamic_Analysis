#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <stdio.h>

int main() {
    pid_t child;
    struct user_regs_struct regs;
    long params[3];
    int status;
    int insyscall = 0;
    child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/ls", "ls", NULL);
    } else {
        while (1) {
            wait(&status);
            if (WIFEXITED(status))
                break;
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            if (regs.orig_rax == 1) {  // 系统调用号 1 对应 write
                if (insyscall == 0) {
                    /* Syscall entry */
                    insyscall = 1;
                    params[0] = regs.rdi;
                    params[1] = regs.rsi;
                    params[2] = regs.rdx;
                    printf("Write called with %ld, %ld, %ld\n",
                           params[0], params[1], params[2]);
                } else { /* Syscall exit */
                    printf("Write returned with %lld\n", regs.rax);
                    insyscall = 0;
                }
            }
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        }
    }
    return 0;
}
