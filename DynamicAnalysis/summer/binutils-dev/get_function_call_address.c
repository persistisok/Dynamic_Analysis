#include <stdio.h>
#include <stdlib.h>
#include <bfd.h>
#include <dis-asm.h>

#define DISASSEMBLER_SUCCESS 0
// Callback function to process each function call
static void process_function_call(bfd *abfd, asection *section, const bfd_vma *pc, void *data)
{
    // Check if the current instruction is a function call
    if (dis_asm_insn(abfd, section, pc) == DISASSEMBLER_SUCCESS)
    {
        const char *insn_mnemonic = dis_get_insn_mnemonic(abfd, section, pc);
        if (insn_mnemonic && strcmp(insn_mnemonic, "call") == 0)
        {
            // Print the address of the function call
            printf("Function called at address: 0x%lx\n", *pc);
        }
    }
}

int main(int argc, char* argv[])
{
    // Check if the correct number of arguments are provided
    if (argc != 3)
    {
        printf("Usage: ./function_call_address <executable_file> <function_name>\n");
        return 1;
    }

    const char* executable_file = argv[1];
    const char* function_name = argv[2];

    // Initialize the BFD library
    bfd_init();

    // Open the executable file
    bfd *abfd = bfd_openr(executable_file, NULL);
    if (!abfd)
    {
        fprintf(stderr, "Failed to open executable file\n");
        return 1;
    }

    // Check if the executable file is in a recognized format
    if (!bfd_check_format(abfd, bfd_object))
    {
        fprintf(stderr, "Unrecognized file format\n");
        bfd_close(abfd);
        return 1;
    }

    // Get the symbol table from the executable file
    if ((bfd_get_file_flags(abfd) & HAS_SYMS) != 0)
    {
        long storage_needed = bfd_get_symtab_upper_bound(abfd);
        if (storage_needed <= 0)
        {
            fprintf(stderr, "Failed to get symbol table\n");
            bfd_close(abfd);
            return 1;
        }

        asymbol **symbol_table = (asymbol**)malloc(storage_needed);
        if (!symbol_table)
        {
            fprintf(stderr, "Failed to allocate memory for symbol table\n");
            bfd_close(abfd);
            return 1;
        }

        long num_symbols = bfd_canonicalize_symtab(abfd, symbol_table);
        if (num_symbols < 0)
        {
            fprintf(stderr, "Failed to read symbol table\n");
            free(symbol_table);
            bfd_close(abfd);
            return 1;
        }

        // Iterate over the symbol table to find the desired function
        for (int i = 0; i < num_symbols; i++)
        {
            asymbol *symbol = symbol_table[i];
            const char *symbol_name = bfd_asymbol_name(symbol);

            if (strcmp(symbol_name, function_name) == 0)
            {
                // Get the section and address of the function
                bfd_vma function_addr = bfd_asymbol_value(symbol);
                asection *function_section = bfd_get_section(symbol);

                // Iterate over the instructions to find function calls
                disassemble_info disasm_info;
                init_disassemble_info(&disasm_info, stdout, fprintf);
                disasm_info.flavour = bfd_target_unknown_flavour;
                disasm_info.arch = bfd_get_arch(abfd);
                disasm_info.mach = bfd_get_mach(abfd);
                disasm_info.read_memory_func = bfd_get_section_contents;
                disasm_info.application_data = abfd;
                bfd_map_over_sections(abfd, process_function_call, NULL);

                break;
            }
        }

        free(symbol_table);
    }

    // Clean up and exit
    bfd_close(abfd);

    return 0;
}
