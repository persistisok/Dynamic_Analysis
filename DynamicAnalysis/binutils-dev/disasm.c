#include <stdio.h>
#include <stdlib.h>
#include <bfd.h>
#include <dis-asm.h>

int main(int argc, char *argv[])
{
    if (argc <= 1)
    {
        printf("Usage: %s <binary file>\n", argv[0]);
        return 0;
    }
    
    const char *filename = argv[1];
    bfd *abfd = bfd_openr(filename, NULL);

    if (abfd == NULL)
    {
        perror("bfd_openr");
        return 1;
    }

    disassemble_info disasm_info = {
        .flavour = bfd_target_unknown_flavour,
        .arch = bfd_get_arch(abfd),
        .mach = bfd_get_mach(abfd),
        .endian = bfd_big_endian(abfd) ? BFD_ENDIAN_BIG : BFD_ENDIAN_LITTLE,
        .buffer_length = bfd_get_size(abfd),
        .buffer = malloc(bfd_get_size(abfd)),
        .private_data = NULL,
    };

    if (!bfd_check_format(abfd, bfd_object))
    {
        perror("bfd_check_format");
        return 1;
    }

    if (!bfd_get_section_contents(abfd, bfd_get_section_by_name(abfd, ".text"), disasm_info.buffer, 0, disasm_info.buffer_length))
    {
        perror("bfd_get_section_contents");
        return 1;
    }
    bfd_map_over_sections(abfd, , &disasm_info);



    free(disasm_info.buffer);
    bfd_close(abfd);
    return 0;
}