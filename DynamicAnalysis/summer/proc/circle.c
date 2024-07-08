#include<stdio.h>
#include <unistd.h>
extern void print_sentence(const char* sentence);
void start(){
	printf("It's an infinite loop.\n");
}
int main(){
    int i = 0;
    start();
    while(1){
        sleep(1);
        print_sentence("This is a sentence from original program.");
    }
    return 0;
}
