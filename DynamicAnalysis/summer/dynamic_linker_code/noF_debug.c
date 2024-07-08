#include<stdio.h>
#include<dlfcn.h>
extern void F1(int i);
void G(){
	printf("hello,world");
}
int main(){
    dlopen("1",1);
    int i = 0;
    G();
    for(;i<10;i++){
    	F1(i);
    }
    printf("\n");
    return 0;
}
