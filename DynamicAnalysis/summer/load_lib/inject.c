#include <stdio.h>
 
__attribute__((constructor)) void init3(void) {
    printf("library libInject.so loaded!\n");
}
 
__attribute__((destructor)) void fini3(void) {
    printf("library libInject.so unloaded!\n");
}


void print_sentence_inject(void)
{
	printf("This is a sentence that has been replaced.\n");
}
