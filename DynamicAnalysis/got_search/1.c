#include<stdio.h>
void showmsg(char *szMsg)
{
printf("%s\n", szMsg);
}
int main(int argc, char **argv)
{
char szMsg[] = "Hello, world!";
showmsg(szMsg);
return 0;
}