#include<stdio.h>
extern void F(int i);
extern void F1(int i);
void G(){
	printf("hello,world");
}
int main(){
    int i = 0;
    G();
    F(i++);
    F(i++);
    F(i++);
    G();
    for(;i<10;i++){
    	F1(i);
    }
    return 0;
}
