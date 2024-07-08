#include<stdio.h>
#include <dlfcn.h>
int main(){
    dlopen("./libInject1.so",1);
    return 0;
}