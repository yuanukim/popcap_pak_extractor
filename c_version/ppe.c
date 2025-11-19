#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "popcap_pak_extract.h"

int is_dir_exist(const char* path) {
    DWORD dwAttrib = GetFileAttributes(path);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES 
        && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

const char* format_windows_filetime(FILETIME* ft) {
    static char buf[32];
    time_t timestamp;
    struct tm* timeinfo;
    ULARGE_INTEGER ull;
    
    ull.LowPart = ft->dwLowDateTime;
    ull.HighPart = ft->dwHighDateTime;

    /* 
        windows file time begins from 1601/01/01, but unix timestamp 
        begins from 1970/01/01, so we have to minus this duration, 
        that's where 11644473600LL seconds come from.
        
        uli.QuadPart accurates to 10 ^ -7 seconds.
    */
    timestamp = (time_t)((ull.QuadPart / 10000000ULL) - 11644473600ULL);
    timeinfo = localtime(&timestamp);
    strftime(buf, sizeof(buf) / sizeof(char), "%Y-%m-%d %H:%M:%S", timeinfo);
    return buf;
}

void save_file_attr_list(const struct PPE_Context* ctx, const char* savFilePath) {
    struct PPE_FileAttr* cursor;
    const char* lastWriteTime;
    FILE* savFile = fopen(savFilePath, "w");

    if (savFile == NULL) {
        fprintf(stderr, "failed to open %s\n", savFilePath);
        return;
    }

    cursor = ctx->attrList->head->next;
    while (cursor) {
        lastWriteTime = format_windows_filetime(&(cursor->lastWriteTime));
        fprintf(savFile, "%s, %10d bytes, %s\n", lastWriteTime, cursor->size, cursor->name);
        cursor = cursor->next;
    }

    fclose(savFile);
    printf("save file attributes list success, data has been written to file: %s\n", savFilePath);
}

int main(int argc, char* argv[]) {
    int err;
    struct PPE_Context ctx;

    if (argc != 3) {
        fprintf(stderr, "popcap pak extractor: usage: %s <name.pak> <sav_dir>\n", argv[0]);
        return 1;
    }

    if (is_dir_exist(argv[2])) {
        fprintf(stderr, "given dir: \"%s\" is already exists\n", argv[2]);
        return 1;
    }

    err = ppe_init_context(&ctx, argv[1]);
    if (err != PPE_ERR_SUCCESS) {
        fprintf(stderr, "init context failed, %d, %s\n", err, ppe_errmsg(err));
        return 1;
    }

    err = ppe_parse_header(&ctx);
    if (err != PPE_ERR_SUCCESS) {
        ppe_destory_context(&ctx);
        fprintf(stderr, "parse header failed, %d, %s\n", err, ppe_errmsg(err));
        return 1;
    }

    printf("parse header success, %s has %d files\n", argv[1], ctx.attrList->length);
    printf("parse body...");

    err = ppe_parse_body(&ctx, argv[2]);
    if (err != PPE_ERR_SUCCESS) {
        ppe_destory_context(&ctx);
        fprintf(stderr, "parse body failed, %d, %s\n", err, ppe_errmsg(err));
        return 1;
    }

    printf("parse %s success, data has been written to dir: %s\n", argv[1], argv[2]);
    save_file_attr_list(&ctx, "ppe_file_attributes.txt");

    ppe_destory_context(&ctx);
    return 0;
}
