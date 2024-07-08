#include <stdio.h>
#include <stdlib.h>
#include <libelf.h>
#include <gelf.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <executable>\n", argv[0]);
        return 1;
    }

    // 打开可执行文件
    Elf *elf = elf_begin(0, ELF_C_READ, NULL);
    if (!elf) {
        printf("Failed to open the executable\n");
        return 1;
    }

    // 遍历节区
    Elf_Scn *section = NULL;
    while ((section = elf_nextscn(elf, section)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(section, &shdr) != &shdr) {
            printf("Failed to get section header\n");
            return 1;
        }

        // 找到包含代码的节区
        if (shdr.sh_type == SHT_PROGBITS && (shdr.sh_flags & SHF_EXECINSTR)) {
            Elf_Data *data = elf_getdata(section, NULL);
            if (!data) {
                printf("Failed to get section data\n");
                return 1;
            }

            // 创建反汇编器
            disassemble_info disasm_info;
            init_disassemble_info(&disasm_info, stdout, fprintf);
            disasm_info.arch = bfd_arch_unknown;
            disasm_info.mach = bfd_mach_unknown;

            // 反汇编代码
            bfd_vma pc = shdr.sh_addr;
            bfd_byte *buffer = (bfd_byte *)data->d_buf;
            while (pc < shdr.sh_addr + shdr.sh_size) {
                disasm_info.buffer = buffer;
                disasm_info.buffer_length = data->d_size;

                int length = print_insn_i386(pc, &disasm_info);
                if (length <= 0) {
                    printf("Failed to disassemble instruction at address %lx\n", pc);
                    return 1;
                }

                pc += length;
                buffer += length;
            }
        }
    }

    // 关闭可执行文件
    elf_end(elf);

    return 0;
}
