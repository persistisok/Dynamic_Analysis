#include <stdio.h>
#include <stdlib.h>
#include <bfd.h>
#include <dis-asm.h>

int process_function_call(bfd *abfd, asection *section, void *data)
{
    disassemble_info disasm_info;
    init_disassemble_info(&disasm_info, stdout, fprintf);
    disasm_info.arch = bfd_get_arch(abfd);
    disasm_info.mach = bfd_get_mach(abfd);
    disasm_info.endian = bfd_big_endian(abfd) ? BFD_ENDIAN_BIG : BFD_ENDIAN_LITTLE;
    disasm_info.read_memory_func = bfd_get_section_contents;

    bfd_vma pc;
    bfd_byte buffer[16];
    unsigned int length;

    for (pc = bfd_get_start_address(abfd); pc < bfd_get_end_address(abfd); pc += length)
    {
        length = disasm_insn(abfd, section, pc, buffer, &disasm_info);

        if (length == 0)
            break;

        const char *insn_mnemonic = dis_get_insn_mnemonic(abfd, section, pc, &disasm_info);

        if (insn_mnemonic && strcmp(insn_mnemonic, "CALL") == 0)
            printf("Function call at address: %p\n", (void *)pc);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <executable file> <function name>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    const char *function_name = argv[2];

    bfd *abfd = bfd_openr(filename, NULL);
    if (abfd == NULL)
    {
        printf("Failed to open file: %s\n", filename);
        return 1;
    }

    bfd_check_format(abfd, bfd_object);

    long storage_needed = bfd_get_symtab_upper_bound(abfd);
    asymbol **symbol_table = malloc(storage_needed);
    long num_symbols = bfd_canonicalize_symtab(abfd, symbol_table);

    asection *section;
    for (section = abfd->sections; section != NULL; section = section->next)
    {
        if (section->flags & SEC_ALLOC)
        {
            bfd_map_over_sections(abfd, process_function_call, (void *)function_name);
            break;
        }
    }

    bfd_close(abfd);
    free(symbol_table);

    return 0;
}
