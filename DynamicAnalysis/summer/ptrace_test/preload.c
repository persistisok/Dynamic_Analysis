#include <stdio.h>
#include <unistd.h>

int main() {
    char *const argv[] = {"./victim", NULL};
    char *const envp[] = {"LD_PRELOAD=./lib4.so", NULL};

    execve(argv[0], argv, envp);

    // 如果 execve 执行成功，以下代码不会执行
    perror("execve failed");
    return 1;
}
