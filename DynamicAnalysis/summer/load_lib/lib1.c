#include <stdio.h>
 
extern void goo(void);
 
__attribute__((constructor)) void init1(void) {
    printf("library lib1.so  loaded!\n");
}
 
__attribute__((destructor)) void fini1(void) {
    printf("library lib1.so  unloaded!\n");
}
 
 
void foo(void)
{
	printf("foo\n");
	goo();
}