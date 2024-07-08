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

void print_bytes(unsigned long data) {
    for (int i = 0; i < sizeof(unsigned long); i++) {
        unsigned char byte = (data >> (i * 8)) & 0xff;
        printf("%02x ", byte);
    }
    printf("\n");
}

static int rdfile(const char* path, unsigned char** buf, size_t* len)
{
	int e;
	int fd;
	void* t;
	struct stat st;


	if (0 > stat(path, &st)) {
		return -1;
	}

	if (0 > (fd = open(path, O_RDONLY))) {
		return -1;
	}

	if (0 != (t = malloc(st.st_size))) {
		if (st.st_size == read(fd, t, st.st_size)) {
			close(fd);
			*buf = t;
			*len = st.st_size;
			return 0;
		}
	}

	e = errno;
	free(t);
	close(fd);
	errno = e;

	return -1;
}

/*
 * Writes the @len bytes in @buf at @addr in @pid's address space.
 */
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


int main() {
    pid_t child;
    long data;
    void* lib_address;
    void* func_address;

    struct user_regs_struct regs;

    child = fork();
    
    if (child == 0) {
        // 子进程
        printf("Child start.\n");
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("./noF_debug", "noF_debug", NULL);
    } else {
        // 父进程
        printf("Parent start.\n");

        wait(NULL);
        size_t len;
	    unsigned char* buf;
	    unsigned long bakopc;
	    struct user_regs_struct regs_origin;
	    struct user_regs_struct regs_change;


	    if (0 != rdfile("hello2", &buf, &len)) {
		    perror("Failed to read file hello");
		    return 1;
	    }


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
	    if (0 != wr2mem(child, regs_change.rax, buf, len)) {
		    perror("Failed to write shellcode to memory");
	    	return 1;
	    }

	    /* Redirect execution flow. */
	    if (0 != ptrace(PTRACE_SETREGS, child, 0, &regs_origin)) {
		    perror("Failed to redirect execution");
		    return 1;
	    }

        //locate the GOT
        char maps_path[256];
        sprintf(maps_path, "/proc/%d/maps", child);
        FILE* maps_file = fopen(maps_path, "r");
        unsigned long function_address,main,G;
        if (maps_file != NULL) {
            char line[256];
            while (fgets(line, sizeof(line), maps_file)) {
                if (strstr(line, "noF_debug") != NULL) {
                    // 找到可执行文件所在的行
                    unsigned long start, end;
                    sscanf(line, "%lx-%lx", &start, &end);
                    printf("Addr of ./noF_debug start:%lx\n", start);
                    unsigned long function_offset = 0x3fc8;  // 静态文件中的地址偏移量
                    function_address = start + function_offset;
                    G = start + 0x11a9;
                    main = start + 0x11c5;
                    break;
                }
            }
            fclose(maps_file);
        }
        printf("Addr of ./noF_debug's function F1'GOT:%lx\n", function_address);
        printf("Addr of ./noF_debug's function main:%lx\n", main);
        printf("Address of ./noF_debug's static function G:%lx\n",G);


        ptrace(PTRACE_GETREGS, child ,NULL, &regs);
        // 输出断点触发位置
        printf("address: %llx\n", regs.rip);
        // 保存原始指令数据
        long orig_data = ptrace(PTRACE_PEEKTEXT, child, (void *)main, NULL);

        printf("original code in main : %lx\n",orig_data);
        // 设置断点指令
        data = (orig_data & ~0xFF) | 0xCC;
        ptrace(PTRACE_POKETEXT, child, (void *)main, (void *)data);

        // 恢复子进程运行
        ptrace(PTRACE_CONT, child, NULL, NULL);

        // 等待子进程再次停止，表示断点触发
        wait(NULL);

        ptrace(PTRACE_GETREGS, child ,NULL, &regs);
        // 输出断点触发位置
        printf("Breakpoint hit at address: %llx\n", regs.rip);

         // 恢复原始指令
        ptrace(PTRACE_POKETEXT, child, (void *)(regs.rip-1), (void *)orig_data);

        long data;
        printf("bytes in %llx:\n",regs_change.rax);
        data = ptrace(PTRACE_PEEKDATA, child, regs_change.rax, NULL);
        print_bytes(data);
        ptrace(PTRACE_POKETEXT, child, (void *)function_address,(void *)(G));

        // 继续执行子进程
        ptrace(PTRACE_CONT, child, NULL, NULL);
        wait(NULL);
        printf("Parent end.\n");
    }

    
    return 0;
}
