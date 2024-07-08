#include <stdio.h>
#include <stdlib.h>
#include <capstone/capstone.h>

void disassemble_file(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return;
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t* buffer = (uint8_t*)malloc(file_size);
    if (!buffer) {
        perror("Error allocating memory");
        fclose(file);
        return;
    }

    if (fread(buffer, 1, file_size, file) != file_size) {
        perror("Error reading file");
        fclose(file);
        free(buffer);
        return;
    }

    fclose(file);

    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        perror("Error initializing Capstone");
        free(buffer);
        return;
    }

    count = cs_disasm(handle, buffer, file_size, 0x1000, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) {
            printf("0x%"PRIx64":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }
        cs_free(insn, count);
    } else {
        perror("Error disassembling file");
    }

    cs_close(&handle);
    free(buffer);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    const char* filename = argv[1];
    disassemble_file(filename);

    return 0;
}
