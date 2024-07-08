#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 256

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <executable>\n", argv[0]);
        return 1;
    }

    // 构建命令行参数
    char command[BUFFER_SIZE];
    snprintf(command, BUFFER_SIZE, "objdump -d %s", argv[1]);

    // 执行objdump命令并读取输出
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        printf("Failed to execute objdump command\n");
        return 1;
    }

    // 读取输出并打印到控制台
    char buffer[BUFFER_SIZE];
    while (fgets(buffer, BUFFER_SIZE, fp) != NULL) {
        printf("%s", buffer);
    }

    // 关闭文件指针
    pclose(fp);

    return 0;
}
