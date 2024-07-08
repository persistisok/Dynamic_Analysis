#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef void (*func_ptr_t)();

int main() 
{
    const char* library_path = "/home/cyn/Desktop/DA/multiF/F.so";
    const char* function_name = "F";

    void* lib_handle = dlopen(library_path, RTLD_LAZY);
    if (lib_handle == NULL) {
        printf("Failed to load shared library %s.\n", library_path);
        return -1;
    }

    func_ptr_t function_addr = (func_ptr_t)dlsym(lib_handle, function_name);
    if (function_addr == NULL) {
        printf("Failed to find function %s in shared library %s.\n", function_name, library_path);
        dlclose(lib_handle);
        return -1;
    }

    // 可以通过指针进行调用
    function_addr();

    // 释放句柄
    dlclose(lib_handle);

    return 0;
}
