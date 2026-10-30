/* Copyright (c) Microsoft Corporation. Licensed under the Apache License, Version 2.0. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

static uint32_t random_state = 0x19790531;

static unsigned char next_byte(void) {
    random_state = random_state * 1664525u + 1013904223u;
    return (unsigned char)(random_state >> 24);
}

static void write_file(const char *path, const unsigned char *data, size_t size) {
    FILE *file = fopen(path, "wb");
    if (!file) {
        perror(path);
        exit(1);
    }
    if (fwrite(data, 1, size, file) != size) {
        perror(path);
        fclose(file);
        exit(1);
    }
    if (fclose(file) != 0) {
        perror(path);
        exit(1);
    }
}

int main(int argc, char **argv) {
    enum { INPUT_SIZE = 262144, PREFIX_SIZE = 131072 };
    if (argc != 3) {
        fprintf(stderr, "Usage: generator <plaintext-file> <compressed-output-prefix>\n");
        return 1;
    }
    unsigned char *input = (unsigned char *)malloc(INPUT_SIZE);
    if (!input) {
        fprintf(stderr, "Allocation failed\n");
        return 1;
    }
    for (size_t i = 0; i < PREFIX_SIZE; i += 32) {
        for (size_t j = 0; j < 32; ++j)
            input[i + j] = next_byte();
        memcpy(input + i + 16, input + i, 3);
        input[i + 19] = input[i + 3] ^ 0x80;
    }
    for (size_t i = PREFIX_SIZE; i < INPUT_SIZE; ++i) {
        input[i] = (unsigned char)(((i % 257) / 7 + (i / 257) % 13) * 17);
        if (i % 37 == 0)
            input[i] ^= next_byte() & 15;
    }
    write_file(argv[1], input, INPUT_SIZE);
    for (int level = 0; level <= 9; ++level) {
        z_stream stream = {0};
        if (deflateInit2(&stream, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
            fprintf(stderr, "deflateInit2 failed for level %d\n", level);
            return 1;
        }
        uLong bound = deflateBound(&stream, INPUT_SIZE);
        unsigned char *output = (unsigned char *)malloc(bound);
        if (!output) {
            fprintf(stderr, "Allocation failed\n");
            deflateEnd(&stream);
            return 1;
        }
        stream.next_in = input;
        stream.avail_in = INPUT_SIZE;
        stream.next_out = output;
        stream.avail_out = (uInt)bound;
        int result = deflate(&stream, Z_FINISH);
        if (result != Z_STREAM_END) {
            fprintf(stderr, "deflate failed for level %d: %d\n", level, result);
            deflateEnd(&stream);
            free(output);
            return 1;
        }
        char path[4096];
        int length = snprintf(path, sizeof(path), "%s%d.deflate", argv[2], level);
        if (length < 0 || (size_t)length >= sizeof(path)) {
            fprintf(stderr, "Output path is too long\n");
            deflateEnd(&stream);
            free(output);
            return 1;
        }
        write_file(path, output, stream.total_out);
        printf("level=%d bytes=%lu\n", level, stream.total_out);
        if (deflateEnd(&stream) != Z_OK) {
            fprintf(stderr, "deflateEnd failed\n");
            free(output);
            return 1;
        }
        free(output);
    }
    free(input);
    return 0;
}
