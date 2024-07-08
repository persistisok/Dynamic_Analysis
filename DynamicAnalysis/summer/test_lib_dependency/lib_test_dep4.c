#include<stdio.h>
extern void f5();
void f4(){
    printf("this is 4.so\n");
    f5();
}