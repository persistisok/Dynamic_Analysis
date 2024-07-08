#include<stdio.h>
int main(){
    int i = 1;
    while(i == 1){
        sleep(10);
        printf("10 seconds later\n");
    }
    return 0;
}