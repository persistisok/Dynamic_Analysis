#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
// 数据结构表示内存映射区域
typedef struct MemoryRegion {
    unsigned long start;
    unsigned long end;
    struct MemoryRegion* next;
} MemoryRegion;

// 函数用于解析 /proc/pid/maps 文件，并返回一个链表，表示空闲区域
MemoryRegion* find_free_memory_regions(pid_t pid) {
    char filename[20];
    sprintf(filename, "/proc/%d/maps", pid);

    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return NULL;
    }

    MemoryRegion* head = NULL;
    MemoryRegion* current = NULL;

    unsigned long prev_end = 0;

    // 读取文件内容并解析
    while (1) {
        unsigned long start, end;
        if (fscanf(file, "%lx-%lx", &start, &end) != 2) {
            break;  // 读取失败或到达文件末尾
        }

        char line[256];
        fgets(line, sizeof(line), file);  // 读取整行内容，但不使用

        // 计算空闲区域
        if (prev_end < start && prev_end != 0) {
            MemoryRegion* free_region = malloc(sizeof(MemoryRegion));
            free_region->start = prev_end;
            free_region->end = start;
            free_region->next = NULL;

            // 添加到链表
            if (current != NULL) {
                current->next = free_region;
            } else {
                head = free_region;
            }

            current = free_region;
        }

        prev_end = end;
    }

    fclose(file);
    return head;
}

// 函数释放链表内存
void free_memory_regions(MemoryRegion* head) {
    while (head != NULL) {
        MemoryRegion* temp = head;
        head = head->next;
        free(temp);
    }
}

// 函数打印链表内容
void print_memory_regions(MemoryRegion* head) {
    while (head != NULL) {
        printf("Start: %lx, End: %lx\n", head->start, head->end);
        head = head->next;
    }
}

// 函数找到空闲区域中最小的地址，差异在32位带符号整数范围内且是0x1000的倍数
unsigned long find_min_address(MemoryRegion* head, unsigned long target_addr) {
    unsigned long upper_bound = target_addr + 0x7FFFFFFF;
    unsigned long lower_bound = target_addr > (u_int32_t)(1 << 31)? target_addr - (u_int32_t)(1 << 31):0;
    // printf("lower:%lx,upper:%lx\n",lower_bound,upper_bound);
    while (head != NULL) {
        // 检查节点的start和end是否在目标地址的上下界范围内
        if ((head->start >= lower_bound && head->start <= upper_bound))
            return head->start;
        else if(head->end >= lower_bound && head->end <= upper_bound)
        {
            if(lower_bound % 0x1000 == 0)
                return lower_bound;
            else
                return lower_bound - lower_bound%0x1000 + 0x1000;
        }

        head = head->next;
    }

    return 0;
}

unsigned long get_free_mem(pid_t pid, unsigned long target_addr){
    MemoryRegion* free_regions = find_free_memory_regions(pid);

    if (free_regions != NULL) {
        // printf("Free Memory Regions:\n");
        // print_memory_regions(free_regions);
        unsigned long free_mem = find_min_address(free_regions,target_addr);
        // printf("%lx\n",free_mem);
        return free_mem;
    }
}
