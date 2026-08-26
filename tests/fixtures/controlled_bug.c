/* Controlled positive test fixture; this is intentionally not a third-party bug. */
#include <stdlib.h>

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    char *buffer = (char *)malloc(1);
    if (buffer == NULL) {
        return 0;
    }
    buffer[1] = 'X';
    free(buffer);
    return 0;
}
