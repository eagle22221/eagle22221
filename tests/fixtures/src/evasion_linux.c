/* Linux fixture for technique detection: calls ptrace(PTRACE_TRACEME), the
   usual self-debugging anti-debug check, and mmaps writable+executable memory. */
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <string.h>
static const char vm[] = "/dev/vboxguest\0vboxservice";
int main(void) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) return 1;
    void *p = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != (void *)-1) memcpy(p, vm, sizeof vm);
    return 0;
}
