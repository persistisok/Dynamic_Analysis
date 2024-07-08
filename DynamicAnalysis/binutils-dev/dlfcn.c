#include <stdio.h>
#include <dlfcn.h>

int main() {
    void *handle;
    void (*func)();
    handle = dlopen("/home/cyn/Desktop/DA/multiF/F.so", RTLD_LAZY);
    if (!handle) {
        printf("Failed to load library\n");
        return 1;
    }

    func = dlsym(handle, "F");
    if (!func) {
        printf("Failed to find function\n");
        dlclose(handle);
        return 1;
    }

    func();

    dlclose(handle);
    return 0;
}

