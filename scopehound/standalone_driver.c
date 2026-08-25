#include <stdio.h>
#include <stdlib.h>

extern int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s INPUT\n", argv[0]);
        return 64;
    }
    FILE *input = fopen(argv[1], "rb");
    if (input == NULL) {
        perror("fopen");
        return 66;
    }
    if (fseek(input, 0, SEEK_END) != 0) {
        fclose(input);
        return 66;
    }
    long length = ftell(input);
    if (length < 0 || fseek(input, 0, SEEK_SET) != 0) {
        fclose(input);
        return 66;
    }
    unsigned char *data = NULL;
    if (length > 0) {
        data = (unsigned char *)malloc((size_t)length);
        if (data == NULL) {
            fclose(input);
            return 71;
        }
        if (fread(data, 1, (size_t)length, input) != (size_t)length) {
            free(data);
            fclose(input);
            return 66;
        }
    }
    fclose(input);
    int result = LLVMFuzzerTestOneInput(data, (size_t)(length < 0 ? 0 : length));
    free(data);
    return result;
}
