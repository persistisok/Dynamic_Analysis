#include <stdio.h>
#include <stdlib.h>
#include <bfd.h>
#include <dis-asm.h>

int print_insn(asection *asect, struct disassemble_info *info)
{
    // char buffer[256];
    // int length = info->read_memory_func(pc, buffer, 16, info);
    // disassemble_info disasm_info = *info;
    // disasm_info.buffer = buffer;
    // disasm_info.buffer_length = length;
    // disasm_info.insn_info_valid = 0;
    // disasm_info.arch = bfd_get_arch(info->section->owner);
    // disasm_info.mach = bfd_get_mach(info->section->owner);
    // disasm_info.display_endian = info->endian;
    // disasm_info.stop_vma = pc + length;
    // disasm_info.application_data = NULL;

    // print_insn_i386(asect->vma, info);
    // return length;
    fprintf(stdout,"121");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <executable>\n", argv[0]);
        return 1;
    }

    bfd *abfd;
    bfd_init();
    abfd = bfd_openr(argv[1], NULL);
    if (!abfd) {
        printf("Error opening file: %s\n", argv[1]);
        return 1;
    }

    if (!bfd_check_format(abfd, bfd_object)) {
        printf("Invalid file format: %s\n", argv[1]);
        return 1;
    }

    asection *section = bfd_get_section_by_name(abfd, ".text");
    if (!section) {
        printf("Failed to find .text section\n");
        return 1;
    }

    disassemble_info disasm_info;
    init_disassemble_info(&disasm_info, stdout, fprintf);
    disasm_info.arch = bfd_get_arch(abfd);
    disasm_info.endian = bfd_big_endian(abfd) ? BFD_ENDIAN_BIG : BFD_ENDIAN_LITTLE;
    disasm_info.section = section;
    disasm_info.mach = bfd_get_mach(abfd);
    disasm_info.read_memory_func = bfd_get_section_contents;

    bfd_vma vma = bfd_section_vma(section);
    bfd_size_type size = bfd_section_size(section);
    bfd_byte *buffer = (bfd_byte *) malloc(size);
    bfd_get_section_contents(abfd, section, buffer, 0, size);

    disasm_info.buffer = buffer;
    disasm_info.buffer_length = size;

    // bfd_map_over_sections(abfd, print_insn, &disasm_info);

    print_insn_i386(vma, &disasm_info);


    bfd_close(abfd);
    free(buffer);

    return 0;
}
