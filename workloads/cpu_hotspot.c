#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

volatile uint64_t sink = 0;

__attribute__((noinline)) static void hot_func(void) {
    for (uint64_t i = 0; i < 500000000ULL; i++) {
        sink += i % 7;
    }
}

__attribute__((noinline)) static void cold_func(void) {
    for (uint64_t i = 0; i < 10000000ULL; i++) {
        sink += i % 3;
    }
}

int main(void) {
    printf("cpu_hotspot started, pid=%d\n", getpid());
    fflush(stdout);

    while (1) {
        hot_func();
        cold_func();
        sleep(1);
    }

    return 0;
}
