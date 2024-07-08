#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BUFFER_SIZE 256

// 根据指令操作码解析指令助记符
const char *get_instruction_mnemonic(uint8_t opcode) {
    switch (opcode) {
        // 根据指令集的规则，返回相应的指令助记符
        case 0x90: return "nop";
        case 0xc3: return "ret";
        // 其他指令...
        default: return "unknown";
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <executable>\n", argv[0]);
        return 1;
    }

    // 打开可执行文件
    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        printf("Failed to open executable\n");
        return 1;
    }

    // 读取文件内容
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *file_buffer = (uint8_t *) malloc(file_size);
    if (file_buffer == NULL) {
        printf("Failed to allocate memory\n");
        fclose(fp);
        return 1;
    }
    fread(file_buffer, file_size, 1, fp);
    fclose(fp);

    // 反汇编文件内容
    int offset = 0;
    while (offset < file_size) {
        uint8_t opcode = file_buffer[offset];
        printf("%08x:\t%02x\t%s\n", offset, opcode, get_instruction_mnemonic(opcode));

        offset++;
    }

    // 释放内存
    free(file_buffer);

    return 0;
}
