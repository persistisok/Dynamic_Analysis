#include <stdio.h>
#include <stdlib.h>
#include <bfd.h>
#include <dis-asm.h>


static void find_calls_to_sym(bfd *abfd, bfd_symbol *sym)
{
    asection *sect;
    bfd_vma pc;

    for (sect = abfd->sections; sect != NULL; sect = sect->next) {
        if (!(bfd_get_section_flags(abfd, sect) & SEC_ALLOC)) {
            continue;
        }

        for (pc = bfd_get_section_vma(abfd, sect); pc < bfd_get_section_vma(abfd, sect) + bfd_get_section_size(sect); pc++) {
            disassemble_info info;
            init_disassemble_info(&info, stdout, (fprintf_ftype)fprintf);

            info.arch = bfd_get_arch(abfd);
            info.mach = bfd_get_mach(abfd);

            info.endian = bfd_big_endian(abfd) ? BFD_ENDIAN_BIG : BFD_ENDIAN_LITTLE;

            info.display_endian = info.endian;

            info.octets_per_byte = bfd_octets_per_byte(abfd);

            disassemble_init_for_target(&info);

            char buffer[256];
            int instr_len = print_insn_i386(pc, &info);
            if (instr_len == -1) {
                fprintf(stderr, "Failed to disassemble instruction at address 0x%lx\n", (unsigned long)pc);
                continue;
            }
            if ((instr_len == 5) && (buffer[0] == 0xE8)) {
                bfd_vma offset;

                memcpy(&offset, buffer + 1, sizeof(offset));

                bfd_vma called_at = pc + instr_len + offset;

                if (called_at == sym->section->vma + sym->value) {
                    printf("Called at 0x%lx\n", (unsigned long)pc);
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    bfd_init();

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <executable> <function_name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    bfd *abfd = bfd_openr(argv[1], NULL);
    if (abfd == NULL) {
        fprintf(stderr, "Failed to open executable '%s': %s\n", argv[1], bfd_errmsg(bfd_get_error()));
        exit(EXIT_FAILURE);
    }

    if (!bfd_check_format(abfd, bfd_object)) {
        fprintf(stderr, "'%s' is not an object file\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    const char *symname = argv[2];
    bfd_symbol **symbol_table;

    if ((bfd_get_file_flags(abfd) & HAS_SYMS) == 0 ||
        (bfd_read_minisymbols(abfd, 0, (void **)&symbol_table, NULL) == 0 &&
         bfd_read_minisymbols(abfd, 1, (void **)&symbol_table, NULL) == 0) ) {
        fprintf(stderr, "No symbol table found\n");
        exit(EXIT_FAILURE);
    }

    bfd_symbol *sym;
    for (sym = *symbol_table; sym != NULL; sym = sym->next) {
        /* We're just looking for global functions here */
        if (sym->flags & BSF_FUNCTION && sym->flags & BSF_GLOBAL &&
            strcmp(sym->name, symname) == 0) {
            find_calls_to_sym(abfd, sym);
        }
    }

    bfd_close(abfd);

    return EXIT_SUCCESS;
}
