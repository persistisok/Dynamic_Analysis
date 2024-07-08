#include <stdio.h>
 
__attribute__((constructor)) void init3(void) {
    printf("library libInject.so loaded!\n");
}
 
__attribute__((destructor)) void fini3(void) {
    printf("library libInject.so unloaded!\n");
}


void print_sentence_inject1(void)
{
	printf("This is sentence1 injected.\n");
}

void print_sentence_inject2(void)
{
	printf("This is sentence2 injected.\n");
}
