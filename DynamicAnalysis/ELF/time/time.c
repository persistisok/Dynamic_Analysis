#include <stdio.h>
#include <string.h>

int main(int argc, char**argv)
{
    printf("build date: %s %s\n",  __DATE__, __TIME__);
    return 0;
}
