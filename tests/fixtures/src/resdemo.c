/* Freestanding Windows fixture whose only purpose is to carry the resources
 * in resdemo.rc. The pointer table forces a .reloc section after .rsrc, the
 * layout most real programs have. */
__declspec(dllimport) void __stdcall ExitProcess(unsigned int);

static const char banner[] = "binspect resource demo";
const char *const resdemo_table[] = { banner, banner + 9 };

void entry(void) {
    ExitProcess(resdemo_table[1][0] == 'r' ? 0 : 1);
}
