#include<stdio.h>
extern void f3();
void f2(){
    printf("this is 2.so\n");
    f3();
}