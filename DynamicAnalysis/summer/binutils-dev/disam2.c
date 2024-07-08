#include <stdio.h>
#include <stdlib.h>
#include <bfd.h>
#include <dis-asm.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <executable_file>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];

    bfd *abfd = bfd_openr(filename, NULL);
    if (abfd == NULL) {
        printf("Failed to open file: %s\n", filename);
        return 1;
    }

    if (!bfd_check_format(abfd, bfd_object)) {
        printf("Invalid file format: %s\n", filename);
        bfd_close(abfd);
        return 1;
    }

    disassemble_info disasm_info;
    init_disassemble_info(&disasm_info, stdout, fprintf);
    disasm_info.arch = bfd_get_arch(abfd);
    disasm_info.mach = bfd_get_mach(abfd);

    disasm_info.flavour = bfd_target_unknown_flavour;
    disasm_info.endian = BFD_ENDIAN_LITTLE;

    bfd_boolean success = bfd_disassemble(abfd, &disasm_info);
    if (!success) {
        printf("Disassembly failed\n");
    }

    bfd_close(abfd);
    return 0;
}
