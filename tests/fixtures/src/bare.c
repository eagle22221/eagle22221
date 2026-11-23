/* Freestanding fixture: no libc, static, built for several architectures. */
static const char msg[] = "bare-metal fixture says hi";
volatile int result;

__attribute__((noinline)) int checksum(const char *s) {
    int sum = 0;
    while (*s) sum += *s++;
    return sum;
}

void _start(void) {
    result = checksum(msg);
    for (;;) {}
}
