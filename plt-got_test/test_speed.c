#include<stdio.h>
#include<time.h>
#include<stdlib.h>
extern void add1(long* num);
int main(){
    long *num = malloc(sizeof(long));;
    *num = 0;
    struct timespec begin, end; 
    for(int i = 0; i < 100; i++){
        clock_gettime(CLOCK_REALTIME, &begin);
        for(int j = 0; j < 50000000; j++){
            add1(num);
            add1(num);
        }
        clock_gettime(CLOCK_REALTIME, &end);
        long seconds = end.tv_sec - begin.tv_sec;
        long nanoseconds = end.tv_nsec - begin.tv_nsec;
        double elapsed = seconds + nanoseconds*1e-9;
        printf("%ld  %.3f\n",*num,elapsed);
    }
    free(num);
}