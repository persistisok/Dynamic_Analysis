#include<stdio.h>
extern void f1();
void f3(){
    printf("this is 3.so\n");
    f1();
}