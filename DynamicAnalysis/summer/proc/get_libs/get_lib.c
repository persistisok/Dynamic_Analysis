#include <stdio.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>

void read_dt_needed(Elf *elf) {
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        gelf_getshdr(scn, &shdr);

        if (shdr.sh_type == SHT_DYNAMIC) {
            Elf_Data *data = elf_getdata(scn, NULL);

            for (int i = 0; i < data->d_size / shdr.sh_entsize; ++i) {
                GElf_Dyn dyn;
                gelf_getdyn(data, i, &dyn);

                if (dyn.d_tag == DT_NEEDED) {
                    const char *library_name = elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val);
                    printf("DT_NEEDED: %s\n", library_name);
                }
            }
        }
    }
}

void read_dt_runpath(Elf *elf) {
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        gelf_getshdr(scn, &shdr);

        if (shdr.sh_type == SHT_DYNAMIC) {
            Elf_Data *data = elf_getdata(scn, NULL);

            for (int i = 0; i < data->d_size / shdr.sh_entsize; ++i) {
                GElf_Dyn dyn;
                gelf_getdyn(data, i, &dyn);

                if (dyn.d_tag == DT_RUNPATH) {
                    const char *runpath = elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val);
                    printf("DT_RUNPATH: %s\n", runpath);
                }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <elf_filename>\n", argv[0]);
        return 1;
    }

    const char *elf_filename = argv[1];

    int fd = open(elf_filename, O_RDONLY, 0);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "ELF library initialization failed: %s\n", elf_errmsg(-1));
        close(fd);
        return 1;
    }

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (elf == NULL) {
        perror("elf_begin");
        close(fd);
        return 1;
    }

    read_dt_needed(elf);
    read_dt_runpath(elf);

    elf_end(elf);
    close(fd);

    return 0;
}
