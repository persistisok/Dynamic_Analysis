#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>

void print_library_address(const char* library_name) {
    char maps_file_path[256];
    snprintf(maps_file_path, sizeof(maps_file_path), "/proc/self/maps");

    FILE* file = fopen(maps_file_path, "r");
    if (file == NULL) {
        fprintf(stderr, "Failed to open %s\n", maps_file_path);
        return;
    }

    uintptr_t start_address = 0;
    uintptr_t end_address = 0;
    char line[256];
    int first = 1;
    while (fgets(line, sizeof(line), file)) {
        // printf("1\n");
        if (strstr(line, library_name)) {
            if(first){
                sscanf(line, "%lx-%*x", &start_address);
                first = 0;
            }
            sscanf(line, "%*x-%lx", &end_address);
            printf("Shared library '%s' start address: %p\n", library_name, (void*)start_address);
            printf("Shared library '%s' end address: %p\n", library_name, (void*)end_address);
            // break;
        }
    }

    fclose(file);
}

int main() {
    // 传入共享库的名称
    void* handle = dlopen("/home/cyn/Desktop/DA/summer/ptrace_test/lib4.so", RTLD_LAZY);
    if (handle == NULL) {
        fprintf(stderr, "Failed to open library: %s\n", dlerror());
        return 1;
    }
    unsigned long addr = (unsigned long)(handle,"foo");
    printf("addr:%lx\n",addr);
    print_library_address("lib4.so");

    return 0;
}
