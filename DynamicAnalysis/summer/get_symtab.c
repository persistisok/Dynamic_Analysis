#include <stdio.h>
#include <stdlib.h>
#include <gelf.h>
#include <libelf.h>

Elf32_Addr find_function_address(const char* filename, const char* function_name) {
    Elf *elf;
    Elf_Scn *scn = NULL;
    Elf_Data *data;
    Elf32_Sym *sym;
    const char *name;
    size_t num_symbols, i;

    // 打开可执行文件
    elf_version(EV_CURRENT);
    elf = elf_begin(fileno(fopen(filename, "r")), ELF_C_READ, NULL);

    // 定位符号表
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        Elf32_Shdr *shdr = elf32_getshdr(scn);
        if (shdr->sh_type == SHT_SYMTAB) {
            data = elf_getdata(scn, NULL);
            num_symbols = shdr->sh_size / shdr->sh_entsize;
            break;
        }
    }

    // 遍历符号表
    for (i = 0; i < num_symbols; i++) {
        sym = (Elf32_Sym *)(data->d_buf + (i * sizeof(Elf32_Sym)));
        name = elf_strptr(elf, scn->link, sym->st_name);

        // 查找指定函数的地址
        if (name && strcmp(name, function_name) == 0) {
            elf_end(elf);
            return sym->st_value;
        }
    }

    elf_end(elf);
    return 0;
}

int main() {
    const char* filename = "./lib4.so";
    const char* function_name = "foo";
    Elf32_Addr address = find_function_address(filename, function_name);

    if (address != 0) {
        printf("函数 %s 的地址为: 0x%x\n", function_name, address);
    } else {
        printf("找不到函数 %s\n", function_name);
    }

    return 0;
}
