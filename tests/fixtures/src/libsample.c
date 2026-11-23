/* Shared-library fixture: two exported functions, one hidden helper. */
__attribute__((visibility("hidden"))) int hidden_helper(int x) { return x * 3; }
int sample_add(int a, int b) { return a + b + hidden_helper(0); }
const char *sample_greet(void) { return "greetings from libsample.so"; }
