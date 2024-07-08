#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main() {
    //locate the dlopen
    char maps_path[256];
        sprintf(maps_path, "/proc/%d/maps", getpid());
        FILE* maps_file = fopen(maps_path, "r");
        unsigned long dlopen_addr = 0;
        if (maps_file != NULL) {
            char line[256];
            while (fgets(line, sizeof(line), maps_file)) {
                if (strstr(line, "libc-2.31.so") != NULL) {
                    // 找到可执行文件所在的行
                    unsigned long start, end;
                    sscanf(line, "%lx-%lx", &start, &end);
                    printf("Addr of ./libc.so start:%lx\n", start);
                    unsigned long offset = 0x15f990;  // 静态文件中的地址偏移量
                    dlopen_addr = start + offset;
                    break;
                }
            }
            fclose(maps_file);
        }
    printf("Addr of libc's function _libc_dlopen_mode:%lx\n", dlopen_addr);
    void* (*dlopen_ptr)(const char*, int) = (void* (*)(const char*, int))dlopen_addr;
    void* library_handle = dlopen_ptr("./lib4.so", 1);
    return 0;
}