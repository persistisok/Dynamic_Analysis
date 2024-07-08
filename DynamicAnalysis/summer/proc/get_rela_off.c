#include <stdio.h>
#include <stdlib.h>
#include <gelf.h>
#include <libelf.h>
#include <fcntl.h>
#include <string.h>

unsigned long get_rela_off(const char* filename, const char* func_name) {
    // 打开可执行文件
    unsigned long offset = 0;
    int fd = open(filename, O_RDONLY);//O_RDONLY：只读方式打开文件。如果出现错误，它将返回-1
    if (fd < 0) {
        perror("open");
        exit(1);
    }

    // 初始化 libelf
    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "libelf initialization failed: %s\n", elf_errmsg(-1));
        exit(1);
    }

    // 打开 ELF 文件
    Elf* elf = elf_begin(fd, ELF_C_READ, NULL);
    if (elf == NULL) {
        fprintf(stderr, "elf_begin failed: %s\n", elf_errmsg(-1));
        exit(1);
    }

    // 获取 ELF 类型
    Elf_Kind kind = elf_kind(elf);
    if (kind != ELF_K_ELF) {
        fprintf(stderr, "%s is not an executable ELF file\n", filename);
        exit(1);
    }

    // 查找符号表节和字符串表节
    Elf_Scn *dynsym_section = NULL;
    Elf_Scn *strtab_section = NULL;
    Elf_Scn *section1 = NULL;
    while ((section1 = elf_nextscn(elf, section1)) != NULL) {

        GElf_Shdr shdr;
        if (gelf_getshdr(section1, &shdr) == NULL) {
            fprintf(stderr, "gelf_getshdr failed: %s\n", elf_errmsg(-1));
            exit(1);
        }

        if (shdr.sh_type == SHT_DYNSYM) {
            dynsym_section = section1;
        }
        if (shdr.sh_type == SHT_STRTAB) {
            strtab_section = section1;
        }
        if (dynsym_section != NULL && strtab_section != NULL) {
            break;
        }
    }

    if (dynsym_section == NULL || strtab_section == NULL) {
        printf("Symbol table or string table section not found.\n");
        exit(1);
    }

    // 获取符号表数据
    Elf_Data *symtab_data = elf_getdata(dynsym_section, NULL);
    if (symtab_data == NULL) {
        printf("Failed to get symbol table data.\n");
        exit(1);
    }

    Elf64_Sym *dynsym_entries = (Elf64_Sym *) symtab_data->d_buf;
    size_t num_symbols = symtab_data->d_size / sizeof(Elf64_Sym);
   
    // 获取字符串表数据
    Elf_Data *strtab_data = elf_getdata(strtab_section, NULL);
    if (strtab_data == NULL) {
        printf("Failed to get string table data.\n");
        exit(1);
    }
    char *strtab_entries = (char *) strtab_data->d_buf;
        
    // 遍历节表
    Elf_Scn* section = NULL;
    while ((section = elf_nextscn(elf, section)) != NULL) {
        // 获取节头部信息
        GElf_Shdr shdr;
       
        if (gelf_getshdr(section, &shdr) == NULL) {
            fprintf(stderr, "gelf_getshdr failed: %s\n", elf_errmsg(-1));
            exit(1);
        }

        // 判断是否是重定位表节
        if (shdr.sh_type == SHT_REL || shdr.sh_type == SHT_RELA) {
            size_t shstrndx;
            if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
                // 错误处理
            }

            char* section_name = elf_strptr(elf, shstrndx, shdr.sh_name);
            if (section_name == NULL) {
                fprintf(stderr, "elf_strptr failed: %s\n", elf_errmsg(-1));
                exit(1);
            }

            // printf("Relocation section: %s\n", section_name);

            // 获取重定位表的内容
            Elf_Data* data = elf_getdata(section, NULL);
            if (data == NULL) {
                fprintf(stderr, "elf_getdata failed: %s\n", elf_errmsg(-1));
                exit(1);
            }

            // 解析重定位表的每个条目
            int num_entries = shdr.sh_size / shdr.sh_entsize;
            Elf64_Rela* rel_entries = (Elf64_Rela*)data->d_buf;
            for (int i = 0; i < num_entries; i++) {
                Elf64_Rela rel_entry = rel_entries[i];

                // 获取重定位类型和符号索引
                Elf64_Addr	r_offset = rel_entry.r_offset;
                Elf64_Xword r_info = rel_entry.r_info;
                Elf64_Sxword r_addend = rel_entry.r_addend;

                Elf64_Word r_type = ELF64_R_TYPE(r_info);
                Elf64_Word r_symidx = ELF64_R_SYM(r_info);

                
                Elf64_Sym symbol = dynsym_entries[r_symidx];
            
                char *sym_name = &strtab_entries[symbol.st_name];
                
                if(strcmp(sym_name,func_name) == 0){
                    offset = r_offset;
                    break;
                }
                // printf("Relocation entry %d: name=%s, offset=%lx, type=%d, addend=%ld\n",
                // i, sym_name, r_offset, r_type, r_addend);
            }
        }
    }

    // 关闭 ELF 文件和文件描述符
    elf_end(elf);
    close(fd);

    return offset;
}