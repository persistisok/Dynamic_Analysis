#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

extern unsigned long get_sym_off(const char* elf_file, const char* func_name);
extern unsigned long get_rela_off(const char* filename, const char* func_name);
extern unsigned long get_free_mem(pid_t pid, unsigned long target_addr);
static int wr2mem(pid_t pid, unsigned long addr, const unsigned char* buf, size_t len)
{
	size_t i;
	unsigned long v;

	for (i = 0 ; i < len ; /**/) {
		v = ((unsigned long*)buf)[i/sizeof(unsigned long)];
		// printf("Writing %016lx at 0x%016lx\n", v, addr);
		if (0 != ptrace(PTRACE_POKETEXT, pid, addr, v)) {
			return -1;
		}

		i += sizeof(unsigned long);
		addr += sizeof(unsigned long);
	}

	return 0;
}

unsigned long get_dlopen_addr(pid_t child){
    //locate the dlopen
    char maps_path[256];
    sprintf(maps_path, "/proc/%d/maps", child);
    FILE* maps_file = fopen(maps_path, "r");
    unsigned long dlopen_addr = 0;
    if (maps_file != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), maps_file)) {
            if (strstr(line, "libc.so.6") != NULL) {
                // 找到可执行文件所在的行
                unsigned long start, end;
                sscanf(line, "%lx-%lx", &start, &end);
                unsigned long offset = 0x85480;  // 静态文件中的地址偏移量
                dlopen_addr = start + offset;
                break;
                }
            }
            fclose(maps_file);
        }
    // printf("Addr of libc's function _libc_dlopen_mode:%lx\n", dlopen_addr);
    return dlopen_addr;
}

unsigned long put_lib_path(pid_t child,const unsigned char* path){
    size_t len = strlen(path)+1;
	unsigned long bakopc;
	struct user_regs_struct regs_origin;
	struct user_regs_struct regs_change;
	/* Get the target process's current registers. */
	if (0 != ptrace(PTRACE_GETREGS, child, 0, &regs_origin)) {
	    perror("Failed to read registers (1)");
	    return 1;
	}
    memcpy(&regs_change, &regs_origin, sizeof(regs_origin));
	/*
    * Prepare a call to mmap.
    * Note that ptrace does not need for PROT_WRITE
    */
    regs_change.rax = 9;		/* sys_mmap */
    regs_change.rdi = 0;
    regs_change.rsi = len;
    regs_change.rdx = 5;		/* PROT_READ | PROT_EXEC */
    regs_change.r10 = 0x22;	    /* MAP_PRIVATE | MAP_ANONYMOUS */
    regs_change.r8 = -1;
    regs_change.r9 = 0;
    if (0 != ptrace(PTRACE_SETREGS, child, 0, &regs_change)) {
	    perror("Failed to update registers (1)");
	    return 1;
    }
	/*
    * We'll be replacing the next instruction. Backup the
    * current opcodes.
    */
    bakopc = ptrace(PTRACE_PEEKTEXT, child, regs_origin.rip, 0);
    if (0 != errno) {
	    perror("Failed to read opcodes");
	    return 1;
   	}

	/* Write syscall's opcode as the next instruction to execute. */
    if (0 != ptrace(PTRACE_POKETEXT, child, regs_change.rip, 0x050f)) {
	    perror("Failed to write syscall's opcode to memory");
	    return 1;
  	}
    /* Invoke mmap. */ 
    if (0 != ptrace(PTRACE_SINGLESTEP, child, 0, 0)) {
	    perror("Failed to singlestep");
	    return 1;
    }

	/* Wait for the process to be stopped (under our control). */
    if (child != waitpid(child, 0, 0)) {
	    perror("Failed waiting for target process");
	    return 1;
	}

    /* Get the allocated memory address. */
    if (0 != ptrace(PTRACE_GETREGS, child, 0, &regs_change)) {
	    perror("Failed to read registers (2)");
	    return 1;
    }

	/* Restore the overwritten opcodes. */
    if (0 != ptrace(PTRACE_POKETEXT, child, regs_origin.rip, bakopc)) {
	    perror("Failed to restore opcodes");
	    return 1;
    }

	/* Write shellcode (skipping backed up rip). */
    if (0 != wr2mem(child, regs_change.rax, path, len)) {
	    perror("Failed to write shellcode to memory");
    	return 1;
    }

	/* Redirect execution flow. */
	if (0 != ptrace(PTRACE_SETREGS, child, 0, &regs_origin)) {
	    perror("Failed to redirect execution");
	    return 1;
    }
    return regs_change.rax;
}

void inject_lib(pid_t child, unsigned long lib_addr, unsigned long dlopen_addr){
    struct user_regs_struct r1;
    struct user_regs_struct r2;
    ptrace(PTRACE_GETREGS,child,NULL,&r1);
    ptrace(PTRACE_GETREGS,child,NULL,&r2);
        unsigned long ins = ptrace(PTRACE_PEEKTEXT,child,r1.rip,NULL);
        
        r2.rdi = lib_addr;
        r2.rsi = 1; // RTLD_LAZY
        r2.r9 = dlopen_addr; 
        ptrace(PTRACE_SETREGS,child,0,&r2);

        // call r9; int 3
        ptrace(PTRACE_POKETEXT,child,r1.rip,0xccd1ff41);
        

        ptrace(PTRACE_CONT,child,NULL,NULL);
        waitpid(child,0,0);
        ptrace(PTRACE_SETREGS,child,NULL,&r1);
        ptrace(PTRACE_POKETEXT,child, r1.rip, ins);
}

unsigned long get_func_addr(pid_t child, unsigned char* lib_name, unsigned char* func_name){
    char maps_path[256];
    sprintf(maps_path, "/proc/%d/maps", child);
    FILE* maps_file = fopen(maps_path, "r");
    unsigned long func_addr = 0;
    if (maps_file != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), maps_file)) {
            if (strstr(line, lib_name) != NULL) {
                // 找到可执行文件所在的行
                unsigned long start, end;
                sscanf(line, "%lx-%lx", &start, &end);
                unsigned char lib_path[50] = "./";
                strncat(lib_path, lib_name, strlen(lib_name));
                unsigned long offset = get_sym_off(lib_path,func_name);  // 静态文件中的地址偏移量
                func_addr = start + offset;
                break;
                }
            }
            fclose(maps_file);
        }
    // printf("Addr of libInject's function print_sentence_inject:%lx\n", func_addr);
    return func_addr;
}

unsigned long get_got_addr(pid_t child, unsigned char* prog_name, unsigned char* func_name_origin){
    char maps_path[256];
    sprintf(maps_path, "/proc/%d/maps", child);
    FILE* maps_file = fopen(maps_path, "r");
    unsigned long func_addr = 0;
    if (maps_file != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), maps_file)) {
            if (strstr(line, prog_name) != NULL) {
                // 找到可执行文件所在的行
                unsigned long start, end;
                sscanf(line, "%lx-%lx", &start, &end);
                unsigned char prog_path[50] = "./";
                strncat(prog_path, prog_name, strlen(prog_name));
                unsigned long offset = get_rela_off(prog_path,func_name_origin);
                func_addr = start + offset;
                break;
                }
            }
            fclose(maps_file);
        }
    // printf("Addr of circle's function print_sentence:%lx\n", func_addr);
    return func_addr;
}

unsigned long new_plt_got(pid_t child, unsigned long start_addr, unsigned long func_addr){
	unsigned long bakopc;
	struct user_regs_struct regs_origin;
	struct user_regs_struct regs_change;
	/* Get the target process's current registers. */
	if (0 != ptrace(PTRACE_GETREGS, child, 0, &regs_origin)) {
	    perror("Failed to read registers (1)");
	    return 1;
	}
    memcpy(&regs_change, &regs_origin, sizeof(regs_origin));
	/*
    * Prepare a call to mmap.
    * Note that ptrace does not need for PROT_WRITE
    */
    regs_change.rax = 9;		/* sys_mmap */
    regs_change.rdi = start_addr;
    regs_change.rsi = 24;
    regs_change.rdx = 7;		/* PROT_READ | PROT_WRITE | PROT_EXEC */
    regs_change.r10 = 0x22;	    /* MAP_PRIVATE | MAP_ANONYMOUS */
    regs_change.r8 = -1;
    regs_change.r9 = 0;
    if (0 != ptrace(PTRACE_SETREGS, child, 0, &regs_change)) {
	    perror("Failed to update registers (1)");
	    return 1;
    }
	/*
    * We'll be replacing the next instruction. Backup the
    * current opcodes.
    */
    bakopc = ptrace(PTRACE_PEEKTEXT, child, regs_origin.rip, 0);
    if (0 != errno) {
	    perror("Failed to read opcodes");
	    return 1;
   	}

	/* Write syscall's opcode as the next instruction to execute. */
    if (0 != ptrace(PTRACE_POKETEXT, child, regs_change.rip, 0x050f)) {
	    perror("Failed to write syscall's opcode to memory");
	    return 1;
  	}
    /* Invoke mmap. */ 
    if (0 != ptrace(PTRACE_SINGLESTEP, child, 0, 0)) {
	    perror("Failed to singlestep");
	    return 1;
    }

	/* Wait for the process to be stopped (under our control). */
    if (child != waitpid(child, 0, 0)) {
	    perror("Failed waiting for target process");
	    return 1;
	}
    // printf("after single_step\n");
    /* Get the allocated memory address. */
    if (0 != ptrace(PTRACE_GETREGS, child, 0, &regs_change)) {
	    perror("Failed to read registers (2)");
	    return 1;
    }
    // printf("%llx\n",regs_change.rax);
	/* Restore the overwritten opcodes. */
    if (0 != ptrace(PTRACE_POKETEXT, child, regs_origin.rip, bakopc)) {
	    perror("Failed to restore opcodes");
	    return 1;
    }

    if (0 != ptrace(PTRACE_POKETEXT,child,regs_change.rax,0x0525fff2fa1e0ff3)) {
	    perror("Failed to write shellcode to memory");
    	return 1;
    }

    if (0 != ptrace(PTRACE_POKETEXT,child,regs_change.rax + 8,0x0000441f0f000000)) {
	    perror("Failed to write shellcode to memory");
    	return 1;
    }

    if (0 != ptrace(PTRACE_POKETEXT,child,regs_change.rax + 16,func_addr)) {
	    perror("Failed to write shellcode to memory");
    	return 1;
    }
    // unsigned long ptrace_code = ptrace(PTRACE_PEEKTEXT,child,regs_change.rax,0);
    // printf("ptrace_code: %lx\n",ptrace_code);
    // printf("before redirect\n");
	/* Redirect execution flow. */
	if (0 != ptrace(PTRACE_SETREGS, child, 0, &regs_origin)) {
	    perror("Failed to redirect execution");
	    return 1;
    }
    return regs_change.rax;
}

void modify_target_addr(pid_t child, unsigned long target_addr, unsigned long plt_addr){
    unsigned long origin_text = ptrace(PTRACE_PEEKTEXT, child, target_addr, 0);
    // printf("origin opc:%lx\n",origin_text);
    long offset = plt_addr - target_addr - 5;
    // printf("offset: %lx\n",offset);
    uint64_t result = (origin_text & 0xFFFFFF00000000FF) | (offset << 8 & 0xFFFFFFFF00);
    // printf("result: %lx\n",result);
    ptrace(PTRACE_POKEDATA,child,target_addr,result);
}

unsigned long get_start_addr(pid_t child, unsigned char* lib_name){
    char maps_path[256];
    sprintf(maps_path, "/proc/%d/maps", child);
    FILE* maps_file = fopen(maps_path, "r");
    unsigned long start, end;
    if (maps_file != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), maps_file)) {
            if (strstr(line, lib_name) != NULL) {
                // 找到可执行文件所在的行
                sscanf(line, "%lx-%lx", &start, &end);
                unsigned char lib_path[50] = "./";
                strncat(lib_path, lib_name, strlen(lib_name));
                break;
                }
            }
            fclose(maps_file);
        }
    return start;
}

int main(int argc, const char* argv[]) {

    if (argc != 6) {
        printf("Usage: %s <prog_name> <target_addr> <lib_name> <function_name> <pid>\n", argv[0]);
        return 1;
    }

    pid_t child = atoi(argv[5]);
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) == -1) {
        perror("ptrace attach failed");
        return 1;
    }
    waitpid(child,0,0);

    unsigned char lib_path[50] = "./";
    strncat(lib_path, argv[3], strlen(argv[3]));
    unsigned long lib_addr = put_lib_path(child,lib_path);
    unsigned long dlopen_addr = get_dlopen_addr(child);

    inject_lib(child,lib_addr,dlopen_addr);

    unsigned char lib_name[strlen(argv[3])];
    strcpy(lib_name,argv[3]);
   
    unsigned char prog_name[strlen(argv[1])] ;
    strcpy(prog_name,argv[1]);
    
    unsigned long prog_start_addr = get_start_addr(child, prog_name);
    unsigned long target_addr = strtoul(argv[2], NULL, 16) + prog_start_addr;
    // printf("target_addr: %lx\n",target_addr);
    
    unsigned long start_addr = get_free_mem(child,target_addr);
    unsigned char func_name_inject[strlen(argv[4])];
    strcpy(func_name_inject,argv[4]);
    unsigned long func_addr = get_func_addr(child,lib_name,func_name_inject);
    if(start_addr != 0 && func_addr != 0){
        // printf("start_addr: %lx\nfunc_addr: %lx\n",start_addr,func_addr);
        unsigned long plt_addr = new_plt_got(child,start_addr,func_addr);
        modify_target_addr(child,target_addr,plt_addr);
    }
        
    ptrace(PTRACE_CONT,child,0,0);
    
    waitpid(child,0,0);

    ptrace(PTRACE_DETACH,child,NULL,NULL);

    return 0;
}
