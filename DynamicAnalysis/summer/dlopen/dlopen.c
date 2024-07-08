#include<stdio.h>
#include<dlfcn.h>

int main(){
    void* handle = dlopen("lib1.so",1);
    long addr = dlsym(handle,"foo");
    printf("0x%lx",addr);
    return 0;
}