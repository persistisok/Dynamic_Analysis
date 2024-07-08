#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bfd.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <executable> <function_name>\n", argv[0]);
        return 1;
    }

    bfd_init();

    bfd *abfd = bfd_openr(argv[1], NULL);
    if (abfd == NULL) {
        fprintf(stderr, "Failed to open executable file: %s\n", argv[1]);
        return 1;
    }

    if (!bfd_check_format(abfd, bfd_object)) {
        fprintf(stderr, "File format is not recognized: %s\n", argv[1]);
        bfd_close(abfd);
        return 1;
    }

    char *func_name = argv[2];
    asection *sec;
    bfd_vma pc, start_addr;
    bfd_size_type size;
    unsigned char *buffer;

    for (sec = abfd->sections; sec != NULL; sec = sec->next) {
        if (!(bfd_get_section_flags(abfd, sec) & SEC_CODE)) {
            continue;
        }
        if (strcmp(sec->name, ".text") != 0) {
            continue;
        }

        start_addr = bfd_get_section_vma(abfd, sec);
        size = bfd_get_section_size(sec);
        buffer = (unsigned char *)malloc(size);

        if (!bfd_get_section_contents(abfd, sec, buffer, 0, size)) {
            fprintf(stderr, "Failed to read section %s from executable file: %s\n", sec->name, argv[1]);
            bfd_close(abfd);
            return 1;
        }

        for (pc = 0; pc < size;) {
            int insn_length = bfd_disassemble(abfd, buffer, start_addr, pc, stdout);
            if (insn_length < 0) {
                fprintf(stderr, "Failed to disassemble instruction at address 0x%lx in section %s\n", start_addr + pc, sec->name);
                break;
            }

            char *insn = (char *)malloc(insn_length + 1);
            memset(insn, 0, insn_length + 1);
            memcpy(insn, buffer + pc, insn_length);

            if (strstr(insn, func_name) != NULL &&
                strstr(insn, "call") != NULL) {
                bfd_vma call_addr = start_addr + pc;
                printf("Function %s called at address 0x%lx\n", func_name, call_addr);
            }

            pc += insn_length;
            free(insn);
        }

        free(buffer);
    }

    bfd_close(abfd);
    return 0;
}