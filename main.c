#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define MINIZ_NO_STDIO
#define MINIZ_NO_DEFLATE_APIS
#define MINIZ_NO_ARCHIVE_WRITING_APIS
#define MINIZ_NO_ZLIB_APIS
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#include "miniz/miniz.c"

#include <keystone/keystone.h>

#include "bin.zip.h"

#define OUTPUT_FILE "out"

typedef struct OffsetData {
    const char* build_os;
    const char* build_arch;
    int   size;
    int   offset;
} OffsetData;

const OffsetData offset_data[] = {
    { "linux", "amd64", 100000,     0x340 },
    { "linux", "amd64", 200000,     0x340 },
    { "linux", "amd64", 500000,     0x340 },
    { "linux", "amd64", 1000000,    0x340 },
    { "linux", "amd64", 2000000,    0x340 },
    { "linux", "amd64", 5000000,    0x340 },
    { "linux", "amd64", 10000000,   0x340 },

    { "linux", "arm64", 100000,     0x9390 },
    { "linux", "arm64", 200000,     0x9390 },
    { "linux", "arm64", 500000,     0x9390 },
    { "linux", "arm64", 1000000,    0x9390 },
    { "linux", "arm64", 2000000,    0x9390 },
    { "linux", "arm64", 5000000,    0x9390 },
    { "linux", "arm64", 10000000,   0x9390 },

    { "mac", "amd64", 100000,       0x3900 },
    { "mac", "amd64", 200000,       0x3260 },
    { "mac", "amd64", 500000,       0x1e80 },
    { "mac", "amd64", 1000000,      0x3d60 },
    { "mac", "amd64", 2000000,      0x3b20 },
    { "mac", "amd64", 5000000,      0x3460 },
    { "mac", "amd64", 10000000,     0x2920 },

    { "mac", "arm64", 100000,       0x3900 },
    { "mac", "arm64", 200000,       0x3260 },
    { "mac", "arm64", 500000,       0x1e80 },
    { "mac", "arm64", 1000000,      0x3d60 },
    { "mac", "arm64", 2000000,      0x3b20 },
    { "mac", "arm64", 5000000,      0x3460 },
    { "mac", "arm64", 10000000,     0x2920 },

    { "windows", "amd64", 100000,   0x8e0 },
    { "windows", "amd64", 200000,   0x8e0 },
    { "windows", "amd64", 500000,   0x8e0 },
    { "windows", "amd64", 1000000,  0x8e0 },
    { "windows", "amd64", 2000000,  0x8e0 },
    { "windows", "amd64", 5000000,  0x8e0 },
    { "windows", "amd64", 10000000, 0x8e0 },
};

int main(int argc, char** argv) {
    if (argc != 4) {
        printf("Usage: %s <input_file> <build_os> <build_arch>\n", argv[0]);
        return 1;
    }

    const char* input_file = argv[1];
    const char* build_os = argv[2];
    const char* build_arch = argv[3];

    FILE* f = fopen(input_file, "r");
    if (!f) {
        printf("Failed to open %s\n", input_file);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long source_code_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* source_code = (char*)malloc(source_code_len + 1);
    fread(source_code, 1, source_code_len, f);
    fclose(f);

    source_code[source_code_len] = 0;


    ks_engine* ks;
    ks_arch arch;
    ks_mode mode;

    if (strcmp(build_arch, "amd64") == 0) {
        arch = KS_ARCH_X86;
        mode = KS_MODE_64;
    } else if (strcmp(build_arch, "arm64") == 0) {
        arch = KS_ARCH_ARM64;
        mode = (ks_mode)0;
    } else {
        printf("Invalid build_arch: %s\n", build_arch);
        return 1;
    }

    if (ks_open(arch, mode, &ks) != KS_ERR_OK) {
        printf("Failed to initialize keystone\n");
        return 1;
    }

      size_t statement_count;
      unsigned char *machine_code;
      size_t machine_code_len;


    if (ks_asm(ks, source_code, 0, &machine_code, &machine_code_len, &statement_count) != KS_ERR_OK) {
        printf("failed to assemble code: count=%lu, error=%u\n", statement_count, ks_errno(ks));
        return 1;
    }

    // for (int i = 0; i < machine_code_len; i++) {
    //     printf("%02x ", machine_code[i]);
    // }
    // printf("\n");
    printf("Compiled %lu bytes, %lu statements\n", machine_code_len, statement_count);


    int size = 0, offset = 0;

    for (int i = 0; i < sizeof(offset_data) / sizeof(OffsetData); i++) {
        if (strcmp(offset_data[i].build_os, build_os) == 0 && strcmp(offset_data[i].build_arch, build_arch) == 0) {
            if (offset_data[i].size >= size) {
                size = offset_data[i].size;
                offset = offset_data[i].offset;
                break;
            }
        }
    }

    if (size == 0) {
        printf("No offset data found for %s %s\n", build_os, build_arch);
        return 1;
    }

    const char* ext = build_os[0] == 'w' ? ".exe" : "";

    char filename[100];
    snprintf(filename, sizeof(filename), "%s_%s_%d%s", build_os, build_arch, size, ext);

    mz_zip_archive zip_archive = {0};
    int status = mz_zip_reader_init_mem(&zip_archive, bin_zip, bin_zip_len, 0);
    if (!status) {
        printf("mz_zip_reader_init_mem failed with error %d\n", status);
        return 1;
    }

    mz_zip_archive_file_stat file_stat;
    for (int i = 0; i < (int)mz_zip_reader_get_num_files(&zip_archive); i++) {
        if (!mz_zip_reader_file_stat(&zip_archive, i, &file_stat)) {
            printf("mz_zip_reader_file_stat() failed!\n");
            mz_zip_reader_end(&zip_archive);
            return 1;
        }

        if (!strcmp(file_stat.m_filename, filename)) break;
    }

    char* p = (char*)mz_zip_reader_extract_file_to_heap(&zip_archive, filename, (size_t*)&file_stat.m_uncomp_size, 0);
    if (!p) {
        printf("mz_zip_reader_extract_file_to_heap() failed!\n");
        mz_zip_reader_end(&zip_archive);
        return 1;
    }

    char* file_buf = p + offset;
    memcpy(file_buf, machine_code, machine_code_len);

    if (remove(OUTPUT_FILE) != 0 && errno != ENOENT) {
        printf("Failed to remove old file\n");
        return 1;
    }

    int fd = open(OUTPUT_FILE, O_RDWR | O_CREAT, 0777);
    f = fdopen(fd, "w");
    fwrite(p, 1, file_stat.m_uncomp_size, f);
    fclose(f);

    mz_free(p);
    mz_zip_reader_end(&zip_archive);

    // code signing
    if (strcmp(build_os, "mac") == 0) {
        const char* command = build_os[0] == 'w' ? "rcodesign sign " OUTPUT_FILE " > nul" : "codesign -s - " OUTPUT_FILE " > /dev/null";
        if (system(command) != 0)
#if __APPLE__
            if (system("codesign -s - " OUTPUT_FILE " > /dev/null") != 0)
#endif
            {
                printf("Failed to sign macOS binary. Please install rcodesign:\nhttps://github.com/indygreg/apple-platform-rs/tree/main/apple-codesign\n");
                return 1;
            }
    }

    printf("output written to ./" OUTPUT_FILE "\n");
    return 0;
}
