#include <bfd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h> 

int main(int argc, char *argv[]) {
  bfd* exec_bfd;
  asection* text_section;
  asymbol** symbols;
  long storage_needed, number_of_symbols, i;

  if (argc != 3) {
    printf("Usage: %s <executable> <function>\n", argv[0]);
    return 1;
  }

  bfd_init ();

  exec_bfd = bfd_openr(argv[1], NULL);
  if (! exec_bfd) {
    printf("%s: BFD open failed\n", argv[1]);
    return 1;
  }

  if (! bfd_check_format(exec_bfd, bfd_object)) {
    printf("%s: Not an object file\n", argv[1]);
    return 1;
  }

  storage_needed = bfd_get_symtab_upper_bound (exec_bfd);
  if (storage_needed <= 0) {
    printf("%s: No symbol table found\n", argv[1]);
    return 1;
  }

  symbols = (asymbol**)malloc(storage_needed);
  if (! symbols) {
    printf("%s: Failed to allocate memory for symbol table\n", argv[1]);
    return 1;
  }

  number_of_symbols = bfd_canonicalize_symtab(exec_bfd, symbols);
  if (number_of_symbols < 0) {
    printf("%s: Failed to read symbol table\n", argv[1]);
    return 1;
  }

  for (i = 0; i < number_of_symbols; i ++) {
    if (bfd_asymbol_name(symbols[i]) && strcmp(bfd_asymbol_name(symbols[i]), argv[2]) == 0) {
      printf("Found symbol %s at address 0x%lx\n",
             bfd_asymbol_name(symbols[i]),
             bfd_asymbol_value(symbols[i]));
      break;
    }
  }

  if (i >= number_of_symbols) {
    printf("%s: Symbol not found: %s\n", argv[1], argv[2]);
    return 1;
  }

  text_section = bfd_get_section_by_name(exec_bfd, ".text");
  if (! text_section) {
    printf("%s: .text section not found\n", argv[1]);
    return 1;
  }

  if ((bfd_vma)bfd_asymbol_value(symbols[i]) < text_section->vma ||
      (bfd_vma)bfd_asymbol_value(symbols[i]) >= text_section->vma + text_section->size) {
    printf("%s: Function %s is not located in the text section\n",
           argv[1],
           bfd_asymbol_name(symbols[i]));
    return 1;
  }

  bfd_close(exec_bfd);
  free(symbols);
  return 0;
}
