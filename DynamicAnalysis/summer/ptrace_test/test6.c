#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

unsigned long get_maps_start_addr(pid_t pid, const char* name){
    char maps_path[256];
    sprintf(maps_path, "/proc/%d/maps", pid);
    FILE* maps_file = fopen(maps_path, "r");
    unsigned long start,end;
    int is_find = 0;
    if (maps_file != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), maps_file)) {
            if (strstr(line, name) != NULL) {
                // 找到文件所在的行
                sscanf(line, "%lx-%lx", &start, &end);
                is_find = 1;
                break;
            }
        }
        fclose(maps_file);
        }
    if(!is_find){
        printf("File %s is not found\n",name);
        return 0;
    }
    else{
        printf("Addr of %s's start:%lx\n", name,start);
        return start;
    }
}

void set_breakpoint(pid_t pid, unsigned long addr){
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid ,NULL, &regs);
    // 输出断点触发位置
    printf("addr when setting breakpoint : %llx\n", regs.rip);
    // 保存原始指令数据
    long orig_data = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);

    // 设置断点指令
    long data = (orig_data & ~0xFF) | 0xCC;
    ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)data);

    // 恢复子进程运行
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    // 等待子进程再次停止，表示断点触发
    wait(NULL);

    ptrace(PTRACE_GETREGS, pid ,NULL, &regs);
    // 输出断点触发位置
    printf("Breakpoint hit at address: %llx\n", regs.rip);

    // 恢复原始指令
    ptrace(PTRACE_POKETEXT, pid, (void *)(regs.rip-1), (void *)orig_data);
}

int main() {
    pid_t child;
    void* lib_address;
    void* func_address;

    child = fork();
    
    if (child == 0) {
        // 子进程
        printf("Child start.\n");
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        char *const argv[] = {"./victim", NULL};
        char *const envp[] = {"LD_PRELOAD=./lib4.so", NULL};
        execve(argv[0], argv, envp);
    } else {
        // 父进程
        printf("Parent start.\n");
        wait(NULL);

        //locate the GOT
        unsigned long F1,main,G;
        unsigned long F1_offset = 0x3fc8,main_offset = 0x11a9,G_offset = 0x11c5;
        unsigned long start_victim = get_maps_start_addr(child,"victim");
        if(start_victim == 0){
            return 1;
        }
        F1 = start_victim + F1_offset;
        main = start_victim + main_offset;
        G = start_victim + G_offset;
        printf("Addr of victim's function F1'GOT:%lx\n", F1);
        printf("Addr of victim's function main:%lx\n", main);
        printf("Address of ./victim's static function G:%lx\n",G);



        set_breakpoint(child,main);
        

        //locate the lib
        unsigned long foo;
        unsigned long foo_offset = 0x1147;
        unsigned long start_lib = get_maps_start_addr(child,"lib4.so");
        if(start_lib == 0){
            return 1;
        }
        foo = start_lib + foo_offset;
        printf("Addr of lib4.so's function foo:%lx\n", foo);
        ptrace(PTRACE_POKETEXT, child, (void *)F1,(void *)(foo));


        ptrace(PTRACE_CONT, child, NULL, NULL);
        wait(NULL);
        printf("Parent end.\n");
    }

    
    return 0;
}
