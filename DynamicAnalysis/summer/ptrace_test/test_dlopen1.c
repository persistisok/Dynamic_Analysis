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

static int
wr2mem(pid_t pid, unsigned long addr, const unsigned char* buf, size_t len)
{
	size_t i;
	unsigned long v;

	for (i = 0 ; i < len ; /**/) {
		v = ((unsigned long*)buf)[i/sizeof(unsigned long)];
		if(i==0)printf("Writing %016lx at 0x%016lx\n", v, addr);
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
            if (strstr(line, "libc-2.31.so") != NULL) {
                // 找到可执行文件所在的行
                unsigned long start, end;
                sscanf(line, "%lx-%lx", &start, &end);
                printf("Addr of ./libc.so start:%lx\n", start);
                unsigned long offset = 0x15f990;  // 静态文件中的地址偏移量
                dlopen_addr = start + offset;
                break;
                }
            }
            fclose(maps_file);
        }
    printf("Addr of libc's function _libc_dlopen_mode:%lx\n", dlopen_addr);
    return dlopen_addr;
}

unsigned long get_lib_addr(pid_t child,const unsigned char* path){
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) == -1) {
            perror("ptrace attach failed");
            return 1;
    }
    waitpid(child,0,0);
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
    regs_change.r10 = 0x22;	/* MAP_PRIVATE | MAP_ANONYMOUS */
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
    ptrace(PTRACE_DETACH,child,0,0);
    return regs_change.rax;
}

int main() {
    pid_t child;
    child = fork();
    if (child == 0) {
        // 子进程
        printf("Child start.\n");
        execl("./circle", "circle", NULL);
    } else {
        printf("Parent start.\n");
        sleep(2);
        unsigned char* path = "./lib4.so";
        unsigned long lib_addr = get_lib_addr(child,path);
        printf("lib_addr : %lx\n",lib_addr);

        if (ptrace(PTRACE_ATTACH, child, NULL, NULL) == -1) {
            perror("ptrace attach failed");
            return 1;
    }
    waitpid(child,0,0);
        struct user_regs_struct r1;
	    struct user_regs_struct r2;
        ptrace(PTRACE_GETREGS,child,NULL,&r1);
        ptrace(PTRACE_GETREGS,child,NULL,&r2);
        unsigned long ins = ptrace(PTRACE_PEEKTEXT,child,r1.rip,NULL);
        unsigned long dlopen_addr = get_dlopen_addr(child);
        r2.rdi = lib_addr;
        r2.rsi = 1; // RTLD_LAZY
        r2.r9 = dlopen_addr; 
        ptrace(PTRACE_SETREGS,child,0,&r2);

        // call r9; int 3
        ptrace(PTRACE_POKETEXT,child,r1.rip,0xccd1ff41);
        // ptrace(PTRACE_POKETEXT,child,r1.rip,0xd1ff);
        unsigned long data0 = ptrace(PTRACE_PEEKTEXT,child,dlopen_addr+48,0);
        unsigned long data1 = ptrace(PTRACE_PEEKTEXT,child,r1.rip,0);
        printf("%lx\n",data0);
        printf("%lx\n",data1);
        printf("now's rip : %lx\n",r1.rip);
        printf("rdi : %lx\n",r1.rdi);
        printf("rsi : %lx\n",r1.rsi);
        struct user_regs_struct r;
        ptrace(PTRACE_SINGLESTEP,child,0,0);
        waitpid(child,0,0);
        ptrace(PTRACE_GETREGS,child,NULL,&r);
        printf("1 step's rip : %lx\n",r.rip);
        printf("rdi : %lx\n",r.rdi);
        printf("rsi : %lx\n",r.rsi);

        ptrace(PTRACE_SINGLESTEP,child,0,0);
        waitpid(child,0,0);
        ptrace(PTRACE_GETREGS,child,NULL,&r);
        printf("2 step's rip : %lx\n",r.rip);
        printf("rdi : %lx\n",r.rdi);
        printf("rsi : %lx\n",r.rsi);

        ptrace(PTRACE_SINGLESTEP,child,0,0);
        waitpid(child,0,0);
        ptrace(PTRACE_GETREGS,child,NULL,&r);
        printf("3 step's rip : %lx\n",r.rip);
        printf("rdi : %lx\n",r.rdi);
        printf("rsi : %lx\n",r.rsi);

        ptrace(PTRACE_SINGLESTEP,child,0,0);
        waitpid(child,0,0);
        ptrace(PTRACE_GETREGS,child,NULL,&r);
        printf("4 step's rip : %lx\n",r.rip);
        printf("rdi : %lx\n",r.rdi);
        printf("rsi : %lx\n",r.rsi);

        ptrace(PTRACE_SINGLESTEP,child,0,0);
        waitpid(child,0,0);
        ptrace(PTRACE_GETREGS,child,NULL,&r);
        printf("5 step's rip : %lx\n",r.rip);
        printf("rdi : %lx\n",r.rdi);
        printf("rsi : %lx\n",r.rsi);

        ptrace(PTRACE_SINGLESTEP,child,0,0);
        waitpid(child,0,0);
        ptrace(PTRACE_GETREGS,child,NULL,&r);
        printf("6 step's rip : %lx\n",r.rip);
        printf("rdi : %lx\n",r.rdi);
        printf("rsi : %lx\n",r.rsi);

        ptrace(PTRACE_SINGLESTEP,child,0,0);
        waitpid(child,0,0);
        ptrace(PTRACE_GETREGS,child,NULL,&r);
        printf("7 step's rip : %lx\n",r.rip);
        printf("rdi : %lx\n",r.rdi);
        printf("rsi : %lx\n",r.rsi);

        ptrace(PTRACE_CONT,child,NULL,NULL);
        waitpid(child,0,0);

        ptrace(PTRACE_SETREGS,child,NULL,&r1);
        ptrace(PTRACE_POKETEXT,child, r1.rip, ins);

        ptrace(PTRACE_DETACH,child,NULL,NULL);
        return 0;
    }
}
