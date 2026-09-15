/* Ground-truth FORTIFY fixture. Compile with -O2 -D_FORTIFY_SOURCE=2. */
#include <string.h>

__attribute__((noinline)) int copy_value(const char *source) {
    char target[8];
    strcpy(target, source);
    return target[0];
}

int main(int argc, char **argv) {
    return copy_value(argc > 1 ? argv[1] : "ok");
}
