/* Hosted Linux fixture: dynamically linked, PIE, full RELRO, stack canary. */
#include <stdio.h>
#include <string.h>

static const char *SECRET = "s3cr3t-fixture-key";

__attribute__((noinline)) int add_numbers(int a, int b) { return a + b; }

__attribute__((noinline)) int check_password(const char *input) {
    return strcmp(input, SECRET) == 0;
}

int main(int argc, char **argv) {
    char name[32];
    snprintf(name, sizeof name, "user-%d", argc);
    puts("Hello from the binspect ELF fixture");
    puts(name);
    if (argc > 1 && check_password(argv[1])) {
        printf("Access granted: %d\n", add_numbers(argc, 40));
        return 0;
    }
    puts("Visit http://example.com/docs for help");
    return 1;
}
