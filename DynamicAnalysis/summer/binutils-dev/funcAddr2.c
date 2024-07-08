#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: ./program <executable> <function_name>\n");
        return 1;
    }

    const char* executable = argv[1];
    const char* function_name = argv[2];

    char command[256];
    snprintf(command, sizeof(command), "gdb --batch -ex 'file %s' -ex 'info line %s'", executable, function_name);

    FILE* fp = popen(command, "r");
    if (!fp) {
        printf("Failed to execute command\n");
        return 1;
    }

    char output[256];
    while (fgets(output, sizeof(output), fp) != NULL) {
        if (strstr(output, "line")) {
            char* token = strtok(output, " ");
            while (token != NULL) {
                if (strncmp(token, "0x", 2) == 0) {
                    printf("%s\n", token);
                    break;
                }
                token = strtok(NULL, " ");
            }
        }
    }

    pclose(fp);

    return 0;
}