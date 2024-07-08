#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


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
        execl("./noF_debug", "noF_debug", NULL);
    } else {
        // 父进程
        wait(NULL);

        // 获取函数地址
        char maps_path[256];
        sprintf(maps_path, "/proc/%d/maps", child);
        FILE* maps_file = fopen(maps_path, "r");
        if (maps_file != NULL) {
            char line[256];
            while (fgets(line, sizeof(line), maps_file)) {
                if (strstr(line, "noF_debug") != NULL) {
                    // 找到可执行文件所在的行
                    unsigned long start, end;
                    sscanf(line, "%lx-%lx", &start, &end);
                    unsigned long function_offset = 0x2fc8;  // 静态文件中的地址偏移量
                    unsigned long function_address = start + function_offset;
                    printf("Start addr : %lx\n",start);
                    printf("End addr : %lx\n",end);
                    // printf("Addr of function F1'GOT:%lx\n", function_address);
                    // long data = ptrace(PTRACE_PEEKDATA, child, ((void*)function_address), NULL);
                    // printf("地址 %lx 中的内容：", function_address);
                    // print_bytes(data);
                    printf("Addr of function start:%lx\n", start);
                    int i = 0;
                    while(i<1){
                        long data = ptrace(PTRACE_PEEKDATA, child, ((void*)start), NULL);
                        // printf("地址 %lx 中的内容：", start);
                        print_bytes(data);
                        start+=8;
                        i++;
                    }
                    printf("\n");
                }
            }
            fclose(maps_file);
        }

        ptrace(PTRACE_CONT, child, NULL, NULL);
        wait(NULL);
    }

    return 0;
}
