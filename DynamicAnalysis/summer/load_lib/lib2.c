#include <stdio.h>
 
__attribute__((constructor)) void init2(void) {
    printf("library lib2.so loaded!\n");
}
 
__attribute__((destructor)) void fini2(void) {
    printf("library lib2.so unloaded!\n");
}
 
void goo(void)
{
	printf("goo\n");
}