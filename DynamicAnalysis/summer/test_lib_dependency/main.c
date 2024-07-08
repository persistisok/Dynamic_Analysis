#include<stdio.h>
#include<dlfcn.h>
extern void f1();
extern void f2();
int main(){
    f1();
    f2();
    dlopen("./lib_test_plugin.so",RTLD_LAZY);
    return 0;
}