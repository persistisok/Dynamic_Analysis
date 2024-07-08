#include <stdio.h>
#include <stdlib.h>
#include <elfutils/libdwfl.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <executable>\n", argv[0]);
        return 1;
    }

    // 初始化 DWARF 功能
    Dwfl *dwfl = dwfl_begin(&dwfl_callbacks);
    if (dwfl == NULL) {
        printf("Failed to initialize DWARF functionality\n");
        return 1;
    }

    // 加载可执行程序
    Dwfl_Module *module = dwfl_report_offline(dwfl, argv[1], argv[1], -1);
    if (module == NULL) {
        printf("Failed to load executable\n");
        dwfl_end(dwfl);
        return 1;
    }

    // 获取符号表
    if (dwfl_module_getdwarf(module, NULL) == 0) {
        printf("Failed to get DWARF data\n");
        dwfl_end(dwfl);
        return 1;
    }

    // 迭代程序的符号表
    Dwarf_Addr bias;
    Dwarf_Sym *sym = NULL;
    while ((sym = dwfl_module_nextsym(module, sym)) != NULL) {
        if (dwarf_getsym(sym, &bias) != 0) {
            printf("Failed to get symbol information\n");
            dwfl_end(dwfl);
            return 1;
        }
        printf("Symbol name: %s\n", dwarf_sym_name(sym));
        printf("Symbol value: %lx\n", bias);
        // 进行其他处理
    }

    // 清理资源
    dwfl_end(dwfl);

    return 0;
}
