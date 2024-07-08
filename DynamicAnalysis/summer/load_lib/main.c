#include <stdio.h>
#include <dlfcn.h>
extern void foo();
 
int main(void)
{
	dlopen("11",1);
	printf("input 1 to continue\n");
	scanf("%d");
	foo();
	return 0;
}