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
        sleep(2);
        void *dlopenAddr = (void*)0x7fd01c2a7390;
        const char *libraryPath = "./lib4.so";  // 替换为你要加载的库文件路径

        // 将地址转换为函数指针类型
        void* (*dlopenFunc)(const char *, int) = (void* (*)(const char *, int))dlopenAddr;

        // 调用 dlopen 函数
        void *handle = dlopenFunc(libraryPath, RTLD_LAZY);
        if (handle == NULL) {
            fprintf(stderr, "Failed to load library: %s\n", dlerror());
            return 1;
        }

        // 成功加载库文件，可以进行后续操作

        // 关闭库文件
        dlclose(handle);
        printf("Child end.\n");
    } else {
        // 父进程
        printf("Parent start.\n");
        int attach_result = ptrace(PTRACE_ATTACH, child, NULL, NULL);
        if (attach_result == -1) {
            printf("附加失败，错误号：%d\n", errno);
            return 1;
        }
        printf("成功附加到子进程\n");
        wait(NULL);

        size_t len;
	    unsigned char* buf;
	    unsigned long bakopc;
	    struct user_regs_struct regs_origin;
	    struct user_regs_struct regs_change;
        struct user_regs_struct regs_change1;
	    /* Get the target process's current registers. */
	    if (0 != ptrace(PTRACE_GETREGS, child, 0, &regs_origin)) {
		    perror("Failed to read registers (1)");
		    return 1;
	    }
	    memcpy(&regs_change, &regs_origin, sizeof(regs_origin));
        unsigned char* libraryPath = "./lib4.so";
        len = strlen(libraryPath) + 1;  // 加上字符串结尾的空字符

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

	    
	    /* Write shellcode (skipping backed up rip). */
	    if (0 != wr2mem(child, regs_change.rax, libraryPath, len)) {
		    perror("Failed to write shellcode to memory");
	    	return 1;
	    }

        memcpy(&regs_change1, &regs_origin, sizeof(regs_origin));
        void* handle = dlopen(NULL, RTLD_LAZY); // 获取动态链接器句柄
        void* dlopen_addr = dlsym(handle, "dlopen"); // 获取dlopen函数地址
        printf("Address of dlopen = %p;\n",dlopen_addr);
	    regs_change1.rdi = regs_change.rax;

        
        long data = ptrace(PTRACE_PEEKDATA,child,dlopen_addr,0);
        print_bytes(data);
        
        long callInstruction = 0xe8; // call指令的机器码
        long dlopenOffset = 0x7fd01c2a7390 - (regs_change.rip + sizeof(long)); // dlopen地址的偏移量
        long newRipValue = (regs.rip & ~0xffc) | callInstruction;
        // ptrace(PTRACE_POKETEXT, child, (void*)regs_change1.rip, newRipValue);
        regs_change.rip += sizeof(long) + dlopenOffset;

        // if (0 != ptrace(PTRACE_SETREGS, child, 0, &regs_change1)) {
	    // 	perror("Failed to update registers");
		//     return 1;
	    // }
        // if (0 != ptrace(PTRACE_POKETEXT, child, regs_change.rip, 0xe8)) {
		//     perror("Failed to write syscall's opcode to memory");
		//     return 1;
    	// }

	    
	    // if (0 != ptrace(PTRACE_SINGLESTEP, child, 0, 0)) {
		//     perror("Failed to singlestep");
		//     return 1;
	    // }

	    // if (child != waitpid(child, 0, 0)) {
		//     perror("Failed waiting for target process");
		//     return 1;
    	// }

        /* Restore the overwritten opcodes. */
	    if (0 != ptrace(PTRACE_POKETEXT, child, regs_origin.rip, bakopc)) {
		    perror("Failed to restore opcodes");
		    return 1;
	    }
	    /* Redirect execution flow. */
	    if (0 != ptrace(PTRACE_SETREGS, child, 0, &regs_origin)) {
		    perror("Failed to redirect execution");
		    return 1;
	    }



        ptrace(PTRACE_CONT, child, NULL, NULL);
        wait(NULL);
        printf("Parent end.\n");
    }

    
    return 0;
}
