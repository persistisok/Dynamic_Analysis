#include <stdio.h>
 
__attribute__((constructor)) void init3(void) {
    printf("library lib4.so loaded!\n");
}
 
__attribute__((destructor)) void fini3(void) {
    printf("library lib4.so unloaded!\n");
}


void foo(void)
{
	printf("foo\n");
}
