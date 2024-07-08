#include <stdio.h>
#include <dlfcn.h>
#include<unistd.h>
#include <string.h>
unsigned long get_dlopen_addr(){
    //locate the dlopen
    char maps_path[256];
    sprintf(maps_path, "/proc/%d/maps", getpid());
    FILE* maps_file = fopen(maps_path, "r");
    unsigned long dlopen_addr = 0;
    if (maps_file != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), maps_file)) {
            if (strstr(line, "libc.so") != NULL) {
                // 找到可执行文件所在的行
                unsigned long start, end;
                sscanf(line, "%lx-%lx", &start, &end);
                unsigned long offset = 0x85480;  // 静态文件中的地址偏移量
                dlopen_addr = start + offset;
                break;
                }
            }
            fclose(maps_file);
        }
    printf("Addr of libc's function dlopen:%lx\n", dlopen_addr);
    return dlopen_addr;
}

int main() {
    // 定义一个函数指针，用于指向 dlopen 函数
    void *(*dlopen_ptr)(const char *, int);

    // 假设您已经知道了 dlopen 函数的地址，将其赋值给函数指针
    dlopen_ptr = (void *(*)(const char *, int))get_dlopen_addr(); // 请替换为实际的 dlopen 函数地址

    // 调用 dlopen 函数
    void *handle = dlopen_ptr("./libInject1.so", RTLD_NOW);
    if (handle == NULL) {
        printf("Failed to open library: %s\n", dlerror());
        return 1;
    }

    // 如果加载库成功，您可以进行其他操作，例如查找符号等

    // 关闭库
    dlclose(handle);

    return 0;
}
