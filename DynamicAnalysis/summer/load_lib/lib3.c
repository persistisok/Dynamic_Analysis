#include <stdio.h>
 
__attribute__((constructor)) void init3(void) {
    printf("library lib3.so loaded!\n");
}
 
__attribute__((destructor)) void fini3(void) {
    printf("library lib3.so unloaded!\n");
}