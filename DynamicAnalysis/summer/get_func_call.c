#include <stdio.h>
#include <stdlib.h>
#include <gelf.h>
#include <libelf.h>
#include <capstone/capstone.h>
#include <fcntl.h>

#define ELF_FILE "noF"

int main() {
    // 打开 ELF 文件
    int fd = open(ELF_FILE, O_RDONLY);
    if (fd == -1) {
        perror("Failed to open ELF file\n");
        return 1;
    }

    // 初始化 libelf
    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "Failed to initialize libelf\n");
        return 1;
    }

    // 加载 ELF 文件
    Elf* elf = elf_begin(fd, ELF_C_READ, NULL);
    if (elf == NULL) {
        fprintf(stderr, "Failed to load ELF file\n");
        return 1;
    }

    // 获取 ELF 类型
    Elf_Kind elf_kind_ = elf_kind((elf));
    if (elf_kind_ != ELF_K_ELF) {
        fprintf(stderr, "Not a valid ELF file\n");
        return 1;
    }

    // 获取符号表和字符串表
    Elf_Scn* section = NULL;
    Elf_Data* data = NULL;
    GElf_Shdr shdr;
    Elf_Scn* symtab_section = NULL;
    Elf_Scn* strtab_section = NULL;
    Elf_Data* symtab_data = NULL;
    Elf_Data* strtab_data = NULL;

    while ((section = elf_nextscn(elf, section)) != NULL) {
        if (gelf_getshdr(section, &shdr) != &shdr) {
            fprintf(stderr, "Failed to get section header\n");
            return 1;
        }

        if (shdr.sh_type == SHT_SYMTAB) {
            symtab_section = section;
            symtab_data = elf_getdata(symtab_section, NULL);
        } else if (shdr.sh_type == SHT_STRTAB) {
            strtab_section = section;
            strtab_data = elf_getdata(strtab_section, NULL);
        }
    }

    if (symtab_section == NULL || strtab_section == NULL) {
        fprintf(stderr, "Failed to locate symbol table or string table\n");
        return 1;
    }

    // 遍历符号表，查找目标函数
    int num_symbols = symtab_data->d_size / sizeof(GElf_Sym);
    GElf_Sym* symbols = (GElf_Sym*)symtab_data->d_buf;

    const char* target_function_name = "F";
    GElf_Addr target_function_address = 0;

    for (int i = 0; i < num_symbols; i++) {
        if (gelf_getsym(symtab_data, i, &symbols[i]) != &symbols[i]) {
            fprintf(stderr, "Failed to get symbol\n");
            return 1;
        }

        const char* symbol_name = elf_strptr(elf, 30, symbols[i].st_name);
        if (symbol_name != NULL && strcmp(symbol_name, target_function_name) == 0) {
            target_function_address = symbols[i].st_value;
            printf("%d\n",target_function_address);
            break;
        }
    }

    if (target_function_address == 0) {
        fprintf(stderr, "Failed to find target function\n");
        return 1;
    }

    // 获取代码段
    section = NULL;
    while ((section = elf_nextscn(elf, section)) != NULL) {
        if (gelf_getshdr(section, &shdr) != &shdr) {
            fprintf(stderr, "Failed to get section header");
            return 1;
        }

        if (shdr.sh_type == SHT_PROGBITS && (shdr.sh_flags & SHF_EXECINSTR)) {
            data = elf_getdata(section, NULL);
            break;
        }
    }

    if (data == NULL) {
        fprintf(stderr, "Failed to locate code section");
        return 1;
    }

    // 初始化 Capstone 引擎
    csh handle;
    cs_insn* insn;
    cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    if (err != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone engine");
        return 1;
    }

    // 解析代码段
    size_t num_insns = cs_disasm(handle, (uint8_t*)data->d_buf, data->d_size, 0, 0, &insn);
    if (num_insns == 0) {
        fprintf(stderr, "Failed to disassemble code section");
        return 1;
    }

    // 查找函数调用指令并记录调用位置
    for (size_t i = 0; i < num_insns; i++) {
        if (insn[i].id == X86_INS_CALL) {
            uint64_t call_address = insn[i].address;
            uint64_t target_address = *(uint32_t*)&insn[i].bytes[1] + call_address + insn[i].size;
            if (target_address == target_function_address) {
                printf("Function call at address 0x%llx\n", call_address);
            }
        }
    }

    // 清理资源
    cs_free(insn, num_insns);
    cs_close(&handle);
    elf_end(elf);
    close(fd);

    return 0;
}
