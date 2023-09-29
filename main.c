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

#include "bin.zip.h"


typedef struct OffsetData {
    char* build_os;
    char* build_arch;
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

const char machine_code[] = {
    0xe0, 0x00, 0x00, 0x10, //   adr	  x0, msg          // x0 <- "hello there"
    0x81, 0x17, 0x40, 0xf9, //   ldr     x1, [x28, 40]     // x1 <- stderr
    0x89, 0x57, 0x40, 0xf9, //   ldr     x9, [x28, 168]    // x9 <- fputs
    0x20, 0x01, 0x3f, 0xd6, //   blr     x9                // x9(x0, x1)

    0xa0, 0x08, 0x80, 0x52, //   mov     w0, 69           // x0 <- 69
    0x89, 0x2b, 0x40, 0xf9, //   ldr     x9, [x28, 80]    // x9 <- exit
    0x20, 0x01, 0x3f, 0xd6, //   blr     x9               // x9(x0)


    0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x0a, 0x00
};

const char* build_os = "mac";
const char* build_arch = "arm64";

int main() {
    int machine_code_len = sizeof(machine_code);
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

    char* ext = build_os[0] == 'w' ? ".exe" : "";

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

    char* p = mz_zip_reader_extract_file_to_heap(&zip_archive, filename, (size_t*)&file_stat.m_uncomp_size, 0);
    if (!p) {
        printf("mz_zip_reader_extract_file_to_heap() failed!\n");
        mz_zip_reader_end(&zip_archive);
        return 1;
    }

    char* file_buf = p + offset;
    memcpy(file_buf, machine_code, machine_code_len);

    if (remove("compiled") != 0 && errno != ENOENT) {
        printf("Failed to remove old file\n");
        return 1;
    }

    int fd = open("compiled", O_RDWR | O_CREAT, 0777);
    FILE* f = fdopen(fd, "w");
    fwrite(p, 1, file_stat.m_uncomp_size, f);
    fclose(f);

    mz_free(p);
    mz_zip_reader_end(&zip_archive);

    // code signing
    if (strcmp(build_os, "mac") == 0) {
        const char* command = build_os[0] == 'w' ? "rcodesign sign compiled > nul" : "codesign -s - compiled > /dev/null";
        if (system(command) != 0)
#if __APPLE__
            if (system("codesign -s - compiled > /dev/null") != 0)
#endif
            {
                printf("Failed to sign macOS binary. Please install rcodesign:\nhttps://github.com/indygreg/apple-platform-rs/tree/main/apple-codesign\n");
                return 1;
            }
    }
    return 0;
}
