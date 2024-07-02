#include<stdio.h>
#include <dlfcn.h>
int main(){
    dlopen("/usr/lib/libInject1.so",1);
    return 0;
}