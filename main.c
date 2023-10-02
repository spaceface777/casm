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
#include "thirdparty/miniz/miniz.c"

#include <keystone/keystone.h>

#include "bin.zip.h"

#define OUTPUT_FILE "out.com"

typedef struct OffsetData {
    const char* build_os;
    const char* build_arch;
    int   size;
    int   offset;
} OffsetData;

const OffsetData offset_data[] = {
    { "", "amd64", 100000,     0x5a40 },
    { "", "amd64", 200000,     0x5a40 },
    { "", "amd64", 500000,     0x5a40 },
    { "", "amd64", 1000000,    0x5a40 },
    { "", "amd64", 2000000,    0x5a40 },
    { "", "amd64", 5000000,    0x5a40 },
    { "", "amd64", 10000000,   0x5a40 },
};

int main(int argc, char** argv) {


    if (argc != 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    const char* input_file = argv[1];

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
    ks_arch arch = KS_ARCH_X86;
    ks_mode mode = KS_MODE_64;

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

    printf("Compiled %lu bytes, %lu statements\n", machine_code_len, statement_count);


    int size = 0, offset = 0;

    for (int i = 0; i < sizeof(offset_data) / sizeof(OffsetData); i++) {
        if (strcmp(offset_data[i].build_os, "") == 0 && strcmp(offset_data[i].build_arch, "amd64") == 0) {
            if (offset_data[i].size >= size) {
                size = offset_data[i].size;
                offset = offset_data[i].offset;
                break;
            }
        }
    }

    if (size == 0) {
        printf("No offset data found\n");
        return 1;
    }

    const char* ext = ".com";

    char filename[100];
    snprintf(filename, sizeof(filename), "amd64_%d%s", size, ext);

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

    printf("output written to ./" OUTPUT_FILE "\n");
    return 0;
}
