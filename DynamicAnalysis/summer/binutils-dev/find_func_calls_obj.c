#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUFFER_SIZE 256

void find_function_calls(const char* executable, const char* function_name) {
    char command[MAX_BUFFER_SIZE];
    snprintf(command, MAX_BUFFER_SIZE, "objdump -d %s | grep 'call.*%s' | awk '{print $1}'", executable, function_name);

    FILE* pipe = popen(command, "r");
    if (pipe == NULL) {
        fprintf(stderr, "无法执行objdump命令\n");
        exit(1);
    }

    char buffer[MAX_BUFFER_SIZE];
    while (fgets(buffer, MAX_BUFFER_SIZE, pipe) != NULL) {
        // 移除换行符
        buffer[strcspn(buffer, "\n")] = '\0';
        printf("%s\n", buffer);
    }

    pclose(pipe);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("用法: %s 可执行文件 函数名\n", argv[0]);
        return 1;
    }

    const char* executable = argv[1];
    const char* function_name = argv[2];

    find_function_calls(executable, function_name);

    return 0;
}
