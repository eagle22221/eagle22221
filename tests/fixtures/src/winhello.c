/* Freestanding Windows fixture: imports three KERNEL32 functions. */
typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef unsigned short wchar_t;
#define STD_OUTPUT_HANDLE ((DWORD)-11)

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int);

static const char banner[] = "Hello from the binspect PE fixture\r\n";
const wchar_t wide_banner[] = L"Wide fixture string";
static const char url[] = "https://example.com/update/check";

__declspec(noinline) DWORD text_length(const char *s) {
    DWORD n = 0;
    while (s[n]) n++;
    return n;
}

__declspec(noinline) void print(const char *s) {
    DWORD written;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, text_length(s), &written, 0);
}

void entry(void) {
    print(banner);
    print(url);
    ExitProcess(wide_banner[0] == L'W' ? 0 : 1);
}
