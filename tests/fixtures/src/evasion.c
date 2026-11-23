/* Fixture for technique detection: imports APIs associated with anti-debugging,
   process injection, API hooking and anti-tamper, carries VM-detection strings,
   and keeps a high-entropy section with a packer-style name. It does nothing;
   the imports and section exist only so a static scan has something to find. */
#include "evasion_blob.h"
typedef void *HANDLE; typedef int BOOL; typedef unsigned long DWORD;
typedef unsigned long NTSTATUS; typedef const char *LPCSTR; typedef void *LPVOID;

__declspec(dllimport) BOOL  __stdcall IsDebuggerPresent(void);
__declspec(dllimport) BOOL  __stdcall CheckRemoteDebuggerPresent(HANDLE, BOOL *);
__declspec(dllimport) void  __stdcall OutputDebugStringA(LPCSTR);
__declspec(dllimport) DWORD __stdcall GetTickCount(void);
__declspec(dllimport) LPVOID __stdcall VirtualAllocEx(HANDLE, LPVOID, DWORD, DWORD, DWORD);
__declspec(dllimport) BOOL  __stdcall WriteProcessMemory(HANDLE, LPVOID, const void *, DWORD, DWORD *);
__declspec(dllimport) HANDLE __stdcall CreateRemoteThread(HANDLE, void *, DWORD, void *, void *, DWORD, DWORD *);
__declspec(dllimport) HANDLE __stdcall GetModuleHandleA(LPCSTR);
__declspec(dllimport) NTSTATUS __stdcall NtQueryInformationProcess(HANDLE, int, void *, DWORD, DWORD *);
__declspec(dllimport) HANDLE __stdcall SetWindowsHookExW(int, void *, HANDLE, DWORD);
__declspec(dllimport) void  __stdcall ExitProcess(unsigned int);

/* Driver, service and device names a program checks for to tell it is inside a
   virtual machine or analysis sandbox. These are specific artifacts, not the
   plain vendor words that show up in ordinary software. */
static const char *const vm_markers[] = {
    "VBoxGuest", "vboxservice.exe", "vmci.sys", "vmtoolsd", "qemu-ga", "SbieDll.dll" };

__attribute__((section("UPX1"))) const unsigned char packed_section[512] = {
#include "evasion_section.inc"
};

static volatile DWORD sink;
void entry(void) {
    BOOL dbg = 0;
    sink = IsDebuggerPresent();
    CheckRemoteDebuggerPresent(GetModuleHandleA(0), &dbg);
    OutputDebugStringA(vm_markers[GetTickCount() % 5]);
    NtQueryInformationProcess(GetModuleHandleA(0), 7, 0, 0, 0);
    LPVOID p = VirtualAllocEx(GetModuleHandleA(0), 0, 4096, 0x1000, 0x40);
    WriteProcessMemory(GetModuleHandleA(0), p, packed_blob, sizeof packed_blob, 0);
    CreateRemoteThread(GetModuleHandleA(0), 0, 0, p, 0, 0, 0);
    SetWindowsHookExW(13, p, GetModuleHandleA(0), 0);
    ExitProcess(dbg);
}
