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
    if (argc < 3 || argc > 4 || (argc == 4 && strcmp(argv[3], "no-short") != 0)) {
        fprintf(stderr, "Usage: generator <plaintext-file> <compressed-output-prefix> [no-short]\n");
        return 1;
    }
    int no_short = argc == 4;
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
    if (no_short) {
        for (size_t i = 0; i < INPUT_SIZE; ++i)
            input[i] = next_byte() & 15;
        for (size_t i = 8192; i + 768 < INPUT_SIZE; i += 4096)
            memcpy(input + i, input + i - 4096 + 128, 512);
        /* Bury a repeated prefix beyond both native chain budgets without
           introducing the fourth-byte aliases needed for three-byte matches. */
        for (size_t start = 64; start < 8192; start += 1024) {
            uint32_t target = 0;
            for (size_t j = 0; j < 4; ++j)
                target |= (uint32_t)input[start + j] << (8 * j);
            uint32_t hash = ((target * 66521u + 66521u) >> 16) & 32767u;
            size_t collisions = (start / 1024) % 2 == 0 ? 8 : 129;
            for (size_t collision = 0; collision < collisions; ++collision) {
                uint32_t word;
                do {
                    word = 0;
                    for (size_t j = 0; j < 4; ++j)
                        word |= (uint32_t)(next_byte() & 127) << (8 * j);
                } while ((((word * 66521u + 66521u) >> 16) & 32767u) != hash
                    || (word & 65535u) == (target & 65535u));
                for (size_t j = 0; j < 4; ++j)
                    input[start + 32 + collision * 4 + j] = (unsigned char)(word >> (8 * j));
            }
            memcpy(input + start + 580, input + start, 16);
        }
    }
    write_file(argv[1], input, INPUT_SIZE);
    for (int level = 0; level <= 9; ++level) {
        if (no_short && level != 1 && level != 6)
            continue;
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
