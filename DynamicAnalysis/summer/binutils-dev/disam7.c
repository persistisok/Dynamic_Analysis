#include <stdio.h>
#include <stdlib.h>
#include <bfd.h>
#include <dis-asm.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <executable>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];

    bfd *bfd_handle = bfd_openr(filename, NULL);
    if (bfd_handle == NULL) {
        printf("Failed to open executable\n");
        return 1;
    }

    if (!bfd_check_format(bfd_handle, bfd_object)) {
        printf("Invalid file format\n");
        bfd_close(bfd_handle);
        return 1;
    }

    disassemble_info disasm_info;
    init_disassemble_info(&disasm_info, stdout, (fprintf_ftype)fprintf);
    disasm_info.arch = bfd_get_arch(bfd_handle);
    disasm_info.mach = bfd_get_mach(bfd_handle);
    disasm_info.endian = bfd_big_endian(bfd_handle);

    // 设置缓冲区
    char buffer[256];
    disasm_info.buffer = (bfd_byte *)buffer;
    disasm_info.buffer_vma = 0;
    disasm_info.buffer_length = sizeof(buffer);

    disasm_info.section = NULL;

    bfd_map_over_sections(bfd_handle, disassemble_init_for_target, &disasm_info);

    disasm_info.read_memory_func = buffer_read_memory;
    disasm_info.print_address_func = generic_print_address;
    disasm_info.fprintf_func = (fprintf_ftype)fprintf;

    bfd_vma pc = bfd_get_start_address(bfd_handle);

    bfd_boolean has_end_address = FALSE;

    for (asection *section = bfd_get_section_by_name(bfd_handle, ".text"); section != NULL; section = section->next) {
        bfd_vma section_end = section->vma + section->size;
        printf("%d\n",pc);
        if (!has_end_address || section_end > pc) {
            pc = section_end;
            has_end_address = TRUE;
        }
    }
    print_insn_i386(bfd_get_start_address(bfd_handle), &disasm_info);
    // bfd_vma address;
    // for (address = bfd_get_start_address(bfd_handle); address < pc;) {
    //     int length = print_insn_i386(address, &disasm_info);
    //     address += disasm_info.data_size;
    //     printf("%d\n",length);
    // }

    bfd_close(bfd_handle);
    return 0;
}
