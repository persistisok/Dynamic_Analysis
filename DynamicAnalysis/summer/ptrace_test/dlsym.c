#include <stdio.h>
#include <dlfcn.h>

int main() {
    void *handle;
    int (*add)(int, int);
    char *error;

    handle = dlopen("/home/cyn/Desktop/DA/summer/ptrace_test/lib1.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return 1;
    }

    dlerror(); // 清除错误

    add = dlsym(handle, "foo");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "%s\n", error);
        dlclose(handle);
        return 1;
    }

    printf("Address of 'foo' function: %p\n", (void*)add);

    dlclose(handle);

    return 0;
}
