/* Windows fixture: import by ordinal and a delay-loaded import. */
typedef unsigned long DWORD;

__declspec(dllimport) void __stdcall ExitProcess(unsigned int);
__declspec(dllimport) int __stdcall WSAStartup(unsigned short, void *);
__declspec(dllimport) int __stdcall MessageBoxA(void *, const char *, const char *, unsigned int);

/* Normally supplied by delayimp.lib; never called in this fixture. */
void *__delayLoadHelper2(void *descriptor, void **slot) {
    (void)descriptor; (void)slot;
    return 0;
}

volatile int marker = 0x1234;

void entry(void) {
    WSAStartup(0x0202, 0);
    MessageBoxA(0, "delay-loaded call", "netprobe", 0);
    ExitProcess(marker);
}
