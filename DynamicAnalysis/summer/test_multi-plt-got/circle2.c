#include<stdio.h>
#include <unistd.h>
extern void print_sentence1(const char* sentence);
extern void print_sentence2(const char* sentence);
void start(){
	printf("It's an infinite loop.\n");
}
int main(){
    int i = 0;
    start();
    while(1){
        sleep(1);
        print_sentence1("This is sentence1 from original program.");
        sleep(1);
        print_sentence1("This is sentence2 from original program.");
        sleep(1);
        print_sentence2("This is sentence3 from original program.");
        sleep(1);
        print_sentence2("This is sentence4 from original program.");
    }
    return 0;
}
