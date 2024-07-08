#include <stdio.h>
#include <stdlib.h>
#include <bfd.h>

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: ./program <executable> <function_name>\n");
        return 1;
    }

    const char* executable = argv[1];
    const char* function_name = argv[2];

    bfd_init();

    bfd* binary = bfd_openr(executable, NULL);
    if (!binary) {
        printf("Failed to open binary: %s\n", executable);
        return 1;
    }

    if (!bfd_check_format(binary, bfd_object)) {
        printf("Invalid binary format: %s\n", executable);
        bfd_close(binary);
        return 1;
    }

    long storage_needed = bfd_get_symtab_upper_bound(binary);
    if (storage_needed <= 0) {
        printf("Failed to get symbol table: %s\n", executable);
        bfd_close(binary);
        return 1;
    }

    asymbol** symbols = (asymbol**)malloc(storage_needed);
    long symbol_count = bfd_canonicalize_symtab(binary, symbols);
    if (symbol_count < 0) {
        printf("Failed to process symbol table: %s\n", executable);
        free(symbols);
        bfd_close(binary);
        return 1;
    }

    for (long i = 0; i < symbol_count; i++) {
        asymbol* symbol = symbols[i];
        if (symbol->flags & BSF_FUNCTION) {
            const char* symbol_name = bfd_asymbol_name(symbol);
            if (strcmp(symbol_name, function_name) == 0) {
                bfd_vma symbol_value = bfd_asymbol_value(symbol);
                printf("%s called at address: %lx\n", function_name, symbol_value);
            }
        }
    }

    free(symbols);
    bfd_close(binary);

    return 0;
}
