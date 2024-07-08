#include <stdio.h>
#include <stdlib.h>
#include <bfd.h>
#include <dis-asm.h>

int find_function_calls(const char* filename, const char* function_name) {
    bfd* bfd_file = bfd_openr(filename, NULL);
    if (!bfd_file) {
        fprintf(stderr, "Failed to open file: %s\n", filename);
        return 1;
    }

    if (!bfd_check_format(bfd_file, bfd_object)) {
        fprintf(stderr, "Invalid format: %s\n", filename);
        bfd_close(bfd_file);
        return 1;
    }

    asection* text_section = bfd_get_section_by_name(bfd_file, ".text");
    if (text_section == NULL) {
        fprintf(stderr, "Failed to find .text section\n");
        bfd_close(bfd_file);
        return 1;
    }

    disassemble_info disinfo;
    init_disassemble_info(&disinfo, stdout, fprintf);
    disinfo.arch = bfd_get_arch(bfd_file);
    disinfo.mach = bfd_get_mach(bfd_file);
    disinfo.endian = bfd_big_endian(bfd_file) ? BFD_ENDIAN_BIG : BFD_ENDIAN_LITTLE;
    disinfo.buffer_vma = text_section->vma;
    disinfo.buffer_length = text_section->size;
    disinfo.section = text_section;
    disinfo.print_address_func = bfd_print_address;

    disassemble_init_for_target(&disinfo);

    bfd_vma start_addr = text_section->vma;
    bfd_vma end_addr = text_section->vma + text_section->size;

    disassembler_ftype disassemble_func = disassembler(bfd_file);

    int num_calls = 0;

    for (bfd_vma addr = start_addr; addr < end_addr; ) {
        char buffer[256];
        unsigned int length = disassemble_func(addr, &disinfo);
        if (length == 0) {
            fprintf(stderr, "Failed to disassemble instruction at address 0x%lx\n", addr);
            break;
        }

        const char* mnemonic = buffer;
        const char* operands = strchr(buffer, '\t');
        if (operands != NULL) {
            *operands++ = '\0';
        }

        if (strcmp(operands, function_name) == 0) {
            printf("Call to function %s at address 0x%lx\n", function_name, addr);
            num_calls++;
        }

        addr += length;
    }

    bfd_close(bfd_file);

    return num_calls;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <executable> <function>\n", argv[0]);
        return 1;
    }

    const char* filename = argv[1];
    const char* function_name = argv[2];

    int num_calls = find_function_calls(filename, function_name);
    printf("Found %d calls to function %s\n", num_calls, function_name);

    return 0;
}