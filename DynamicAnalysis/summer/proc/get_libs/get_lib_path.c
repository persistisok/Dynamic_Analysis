#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>

// Function to search for library in specified order
char* search_library(const char *library_name, const char *runpath, const char *ld_library_path) {
    char *library_path = NULL;

    // 1. Search in /etc/ld.so.cache
    FILE *ld_cache_file = fopen("/etc/ld.so.cache", "r");
    if (ld_cache_file != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), ld_cache_file) != NULL) {
            char *token = strtok(line, " \t");
            while (token != NULL) {
                if (strcmp(token, library_name) == 0) {
                    library_path = strdup(token);
                    fclose(ld_cache_file);
                    return library_path;
                }
                token = strtok(NULL, " \t");
            }
        }
        fclose(ld_cache_file);
    }

    // 2. Search in DT_RUNPATH
    if (runpath != NULL && strlen(runpath) > 0) {
        char potential_path[256];
        snprintf(potential_path, sizeof(potential_path), "%s/%s", runpath, library_name);
        if (access(potential_path, F_OK) == 0) {
            library_path = strdup(potential_path);
            return library_path;
        }
    }

    // 3. Search in LD_LIBRARY_PATH
    if (ld_library_path != NULL) {
        char *token = strtok((char *)ld_library_path, ":");
        while (token != NULL) {
            char potential_path[256];
            snprintf(potential_path, sizeof(potential_path), "%s/%s", token, library_name);
            if (access(potential_path, F_OK) == 0) {
                library_path = strdup(potential_path);
                return library_path;
            }
            token = strtok(NULL, ":");
        }
    }

    // 4. Search in default paths (e.g., /lib, /usr/lib)
    const char *default_paths[] = {"/lib", "/lib/x86_64-linux-gnu", "usr/lib",NULL};
    for (int i = 0; default_paths[i] != NULL; ++i) {
        char potential_path[256];
        snprintf(potential_path, sizeof(potential_path), "%s/%s", default_paths[i], library_name);
        if (access(potential_path, F_OK) == 0) {
            library_path = strdup(potential_path);
            return library_path;
        }
    }

    // If not found in any of the paths, return NULL
    return NULL;
}

char* read_dt_runpath(Elf *elf) {
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
                    char *runpath = elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val);
                    printf("DT_RUNPATH: %s\n", runpath);
                    return runpath;
                }
            }
        }
    }
    return NULL;
}

void read_dt_needed(Elf *elf, const char *runpath, const char *ld_library_path) {
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

                    // Search for library in specified order
                    char *library_path = search_library(library_name, runpath, ld_library_path);

                    if (library_path != NULL) {
                        printf("DT_NEEDED: %s (Absolute Path: %s)\n", library_name, library_path);
                        free(library_path);
                    } else {
                        printf("DT_NEEDED: %s (Path not found)\n", library_name);
                    }
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
    char* runpath = read_dt_runpath(elf);
    read_dt_needed(elf, runpath, getenv("LD_LIBRARY_PATH"));

    elf_end(elf);
    close(fd);

    return 0;
}
