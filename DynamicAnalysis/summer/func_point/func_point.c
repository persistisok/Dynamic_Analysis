#include <stdio.h>

// 声明函数指针类型
typedef int (*Operation)(int, int);

// 加法函数
int add(int a, int b) {
    return a + b;
}

// 减法函数
int subtract(int a, int b) {
    return a - b;
}

// 乘法函数
int multiply(int a, int b) {
    return a * b;
}

// 除法函数
int divide(int a, int b) {
    return a / b;
}

int main() {
    int a = 10, b = 5;
    int result;

    // 定义函数指针变量并初始化为加法函数
    Operation operation = add;

    // 使用函数指针调用函数
    result = operation(a, b);
    printf("Result: %d\n", result);

    // 将函数指针指向减法函数
    operation = subtract;
    result = operation(a, b);
    printf("Result: %d\n", result);

    // 将函数指针指向乘法函数
    operation = multiply;
    result = operation(a, b);
    printf("Result: %d\n", result);

    // 将函数指针指向除法函数
    operation = divide;
    result = operation(a, b);
    printf("Result: %d\n", result);

    return 0;
}
