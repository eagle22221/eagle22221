/* Windows DLL fixture: named export, ordinal export, forwarded export. */
__declspec(noinline) int sample_add(int a, int b) { return a + b; }
const char *sample_greet(void) { return "greetings from sample.dll"; }
int __stdcall DllMain(void *instance, unsigned long reason, void *reserved) {
    (void)instance; (void)reason; (void)reserved;
    return 1;
}
