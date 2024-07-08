#include <cstdio>
#include <cstdlib>
#include <bfd.h>
#include <dis-asm.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    bfd_init();
    bfd* bin = bfd_openr(argv[1], NULL);
    if (bin == NULL) {
        printf("Failed to open file: %s\n", bfd_errmsg(bfd_get_error()));
        return EXIT_FAILURE;
    }

    if (!bfd_check_format(bin, bfd_object)) {
        printf("Invalid file format: %s\n", bfd_errmsg(bfd_get_error()));
        bfd_close_all_done(bin);
        return EXIT_FAILURE;
    }

    unsigned int default_arch_size = bfd_get_arch_size(bin->arch_info);

    asection* section = bfd_get_section_by_name(bin, ".text");

    disassemble_info info = {};
    init_disassemble_info(&info, stdout, nullptr);
    info.arch = bfd_get_arch_name(bin);
    info.mach = bfd_get_mach_name(bin);
    if (default_arch_size == 64) {
        info.flavour = bfd_target_elf_flavour;
    } else {
        info.flavour = bfd_target_unknown_flavour;
    }
    info.octets_per_byte = 1; // bytes per char
    info.disassembler_options = "-Mintel";
    disassembler_ftype disassemble_fn = disassembler(bfd_arch_i386, false, 0);

    const size_t buffer_size = 1024;
    uint8_t buffer[buffer_size];
    unsigned long offset = section->filepos;
    const size_t length = bfd_section_size(section);

    while (offset < length) {
        const size_t count = bfd_get_bytes(bin, offset, buffer, buffer_size);
        if (count == 0) {
            printf("Failed to read bytes at offset %lu: %s\n",
                    offset, bfd_errmsg(bfd_get_error()));
            break;
        }

        size_t processed_count = 0;
        while (processed_count < count) {
            const int insn_size = disassemble_fn(offset + processed_count, &info);
            if (insn_size == -1) {
                printf("Failed to disassemble instruction at offset %lu: %s\n",
                        offset + processed_count, info.error_message);
                break;
            }
            processed_count += insn_size;
        }

        offset += count;
    }

    free_disassemble_info(&info);
    bfd_close_all_done(bin);
    return EXIT_SUCCESS;
}