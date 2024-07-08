#include<stdio.h>
extern void F1(int i);
void G(){
	printf("hello,world\n");
}
int main(){
    int i = 0;
    G();
    for(;i<10;i++){
    	F1(i);
    }
    return 0;
}
