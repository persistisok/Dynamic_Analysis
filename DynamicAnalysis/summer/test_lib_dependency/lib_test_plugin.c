#include<stdio.h>
extern void f3();
extern void f4();
void f_plugin(){
    printf("this is plugin.so\n");
    f3();
    f4();
}