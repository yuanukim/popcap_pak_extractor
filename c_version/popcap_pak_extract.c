#include "popcap_pak_extract.h"
#include <stdlib.h>

#define WRITE_BUF_SIZE   8192

#define decode_one_byte(ch) \
    (UCHAR)((ch) ^ 0xf7)

#define decode_bytes(fromBuf, toBuf, length) do { \
    UINT32 i; \
    for (i = 0; i < (UINT32)(length); ++i) { \
        toBuf[i] = decode_one_byte(fromBuf[i]); \
    } \
} while(0)

static const char* win_strerr(DWORD errCode);
static void build_complete_path(char* buf, const char* extractPath, const char* fileName);
static int recursive_create_parent_dirs(char* path);
static int is_dir_exist(const char* path);
static struct PPE_FileAttr* create_file_attr(void);
static struct PPE_FileAttrList* create_file_attr_list(void);
static void file_attr_list_add(struct PPE_FileAttrList* list, struct PPE_FileAttr* attr);
static void destroy_file_attr(struct PPE_FileAttr* attr);
static void destroy_file_attr_list(struct PPE_FileAttrList* list);
static int pak_read(struct PPE_Context* ctx, char* buf, DWORD numOfBytesToRead, DWORD* numOfBytesRead);
static int is_magic_valid(struct PPE_Context* ctx);
static int is_version_valid(struct PPE_Context* ctx);
static int is_the_end_of_header(struct PPE_Context* ctx);
static int pak_parse_end_flag(struct PPE_Context* ctx);
static int pak_parse_magic(struct PPE_Context* ctx);
static int pak_parse_version(struct PPE_Context* ctx);
static int pak_parse_file_name(struct PPE_Context* ctx, struct PPE_FileAttr* attr);
static int pak_parse_file_size(struct PPE_Context* ctx, struct PPE_FileAttr* attr);
static int pak_parse_file_last_write_time(struct PPE_Context* ctx, struct PPE_FileAttr* attr);
static int pak_parse_all_file_attrs(struct PPE_Context* ctx);
static int pak_parse_single_file_body(struct PPE_Context* ctx, struct PPE_FileAttr* attr, const char* extractDir);

static const char* win_strerr(DWORD errCode) {
    static char winErrMsg[1024];
    DWORD success = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                             NULL, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)winErrMsg, sizeof(winErrMsg) / sizeof(char), NULL);
    return success == 0 ? "" : winErrMsg;
}

static void build_complete_path(char* buf, const char* extractPath, const char* fileName) {
    while (*extractPath != '\0') {
        *buf = *extractPath;

        ++buf;
        ++extractPath;
    }

    --extractPath;
    if (*extractPath != '\\') {
        *buf = '\\';
        ++buf;
    }

    while (*fileName != '\0') {
        *buf = *fileName;

        ++buf;
        ++fileName;
    }

    *buf = '\0';
}

static int recursive_create_parent_dirs(char* path) {
    char* cursor = path;

    while (*cursor != '\0') {
        if (*cursor == '\\') {
            /* split a substr here, just make it ends with '\0'. */
            *cursor = '\0';

            if (!is_dir_exist(path)) {
                if (!CreateDirectory(path, NULL)) {
                    return GetLastError();
                }
            }

            /* setting back. */
            *cursor = '\\';
        }

        ++cursor;
    }

    return PPE_ERR_SUCCESS;
}

static int is_dir_exist(const char* path) {
    DWORD dwAttrib = GetFileAttributes(path);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES 
        && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

static struct PPE_FileAttr* create_file_attr(void) {
    struct PPE_FileAttr* attr = (struct PPE_FileAttr*)malloc(sizeof(struct PPE_FileAttr));

    if (attr) {
        attr->name = NULL;
        attr->next = NULL;
    }
    
    return attr;
}

static struct PPE_FileAttrList* create_file_attr_list(void) {
    struct PPE_FileAttrList* list = (struct PPE_FileAttrList*)malloc(sizeof(struct PPE_FileAttrList) + sizeof(struct PPE_FileAttr));
    
    if (list) {
        list->head = list->tail = (struct PPE_FileAttr*)(list + 1);
        list->head->next = NULL;
        list->length = 0;
    }

    return list;
}

static void file_attr_list_add(struct PPE_FileAttrList* list, struct PPE_FileAttr* attr) {
    attr->next = NULL;
    
    list->tail->next = attr;
    list->tail = list->tail->next;
    list->length += 1;
}

static void destroy_file_attr(struct PPE_FileAttr* attr) {
    if (attr) {
        if (attr->name) {
            free(attr->name);
        }

        free(attr);
    }
}

static void destroy_file_attr_list(struct PPE_FileAttrList* list) {
    if (list) {
        struct PPE_FileAttr* cursor = list->head->next;
        struct PPE_FileAttr* temp;

        while (cursor != NULL) {
            temp = cursor;
            cursor = cursor->next;

            destroy_file_attr(temp);
        }

        free(list);
    }
}

static int pak_read(struct PPE_Context* ctx, char* buf, DWORD numOfBytesToRead, DWORD* numOfBytesRead) {
    DWORD readLen;
    
    if (ctx->pakFileSize < numOfBytesToRead) {
        return PPE_ERR_FILE_BROKEN;
    }

    if (!ReadFile(ctx->pakHandle, (LPVOID)buf, numOfBytesToRead, &readLen, NULL)) {
        return GetLastError();
    }

    if (numOfBytesRead != NULL) {
        *numOfBytesRead = readLen;
    }

    ctx->pakFileSize -= readLen;
    return PPE_ERR_SUCCESS;
}

static int is_magic_valid(struct PPE_Context* ctx) {
    return (ctx->magic[0] == 0xc0)
        && (ctx->magic[1] == 0x4a)
        && (ctx->magic[2] == 0xc0)
        && (ctx->magic[3] == 0xba);
}

static int is_version_valid(struct PPE_Context* ctx) {
    return (ctx->version[0] == 0x00)
        && (ctx->version[1] == 0x00)
        && (ctx->version[2] == 0x00)
        && (ctx->version[3] == 0x00);
}

static int is_the_end_of_header(struct PPE_Context* ctx) {
    return ctx->endFlag == 0x80;
}

static int pak_parse_end_flag(struct PPE_Context* ctx) {
    UCHAR flag;
    int err;

    err = pak_read(ctx, (char*)&flag, sizeof(flag), NULL);
    if (err != PPE_ERR_SUCCESS) {
        return err;
    }

    ctx->endFlag = decode_one_byte(flag);
    return PPE_ERR_SUCCESS;
}

static int pak_parse_magic(struct PPE_Context* ctx) {
    int err;

    err = pak_read(ctx, (char*)ctx->magic, sizeof(ctx->magic), NULL);
    if (err != PPE_ERR_SUCCESS) {
        return err;
    }

    decode_bytes(ctx->magic, ctx->magic, PPE_BYTES_OF_MAGIC);

    if (is_magic_valid(ctx)) {
        return PPE_ERR_SUCCESS;
    }
    else {
        return PPE_ERR_INVALID_MAGIC;
    }
}

static int pak_parse_version(struct PPE_Context* ctx) {
    int err;

    err = pak_read(ctx, (char*)ctx->version, sizeof(ctx->version), NULL);
    if (err != PPE_ERR_SUCCESS) {
        return err;
    }

    decode_bytes(ctx->version, ctx->version, PPE_BYTES_OF_MAGIC);
    
    if (is_version_valid(ctx)) {
        return PPE_ERR_SUCCESS;
    }
    else {
        return PPE_ERR_INVALID_VERSION;
    }
}

static int pak_parse_file_name(struct PPE_Context* ctx, struct PPE_FileAttr* attr) {
    int err, fileNameLen;
    char* name;
    UCHAR byte;

    err = pak_read(ctx, (char*)&byte, sizeof(byte), NULL);
    if (err != PPE_ERR_SUCCESS) {
        return err;
    }

    fileNameLen = (int)decode_one_byte(byte);

    name = (char*)malloc((fileNameLen + 1) * sizeof(char));
    if (name == NULL) {
        return PPE_ERR_OUT_OF_MEMORY;
    }

    err = pak_read(ctx, name, fileNameLen * sizeof(char), NULL);
    if (err != PPE_ERR_SUCCESS) {
        free(name);
        return err;
    }

    decode_bytes(name, name, fileNameLen);
    name[fileNameLen] = '\0';
    attr->name = name;
    return PPE_ERR_SUCCESS;
}

static int pak_parse_file_size(struct PPE_Context* ctx, struct PPE_FileAttr* attr) {
    char* buf = (char*)(&(attr->size));
    int err = pak_read(ctx, buf, sizeof(attr->size), NULL);

    if (err != PPE_ERR_SUCCESS) {
        return err;
    }
    else {
        decode_bytes(buf, buf, PPE_BYTES_OF_FILE_SIZE);
        return PPE_ERR_SUCCESS;
    }
}

static int pak_parse_file_last_write_time(struct PPE_Context* ctx, struct PPE_FileAttr* attr) {
    char* buf = (char*)(&(attr->lastWriteTime));
    int err = pak_read(ctx, buf, sizeof(attr->lastWriteTime), NULL);

    if (err != PPE_ERR_SUCCESS) {
        return err;
    }
    else {
        decode_bytes(buf, buf, PPE_BYTES_OF_FILE_TIME);
        return PPE_ERR_SUCCESS;
    }
}

static int pak_parse_all_file_attrs(struct PPE_Context* ctx) {
    struct PPE_FileAttr* attr;
    int err;

    while (1) {
        err = pak_parse_end_flag(ctx);
        if (err != PPE_ERR_SUCCESS) {
            return err;
        }

        if (is_the_end_of_header(ctx)) {
            break;
        }

        attr = create_file_attr();
        if (attr == NULL) {
            return PPE_ERR_OUT_OF_MEMORY;
        }

        err = pak_parse_file_name(ctx, attr);
        if (err != PPE_ERR_SUCCESS) {
            destroy_file_attr(attr);
            return err;
        }

        err = pak_parse_file_size(ctx, attr);
        if (err != PPE_ERR_SUCCESS) {
            destroy_file_attr(attr);
            return err;
        }

        err = pak_parse_file_last_write_time(ctx, attr);
        if (err != PPE_ERR_SUCCESS) {
            destroy_file_attr(attr);
            return err;
        }

        file_attr_list_add(ctx->attrList, attr);
    }

    return PPE_ERR_SUCCESS;
}

static int pak_parse_single_file_body(struct PPE_Context* ctx, struct PPE_FileAttr* attr, const char* extractDir) {
    char writeBuf[WRITE_BUF_SIZE];
    char path[MAX_PATH];
    INT32 fileSize = attr->size;
    INT32 needLen;
    DWORD readLen;
    HANDLE tempFileHandle;
    int err;

    build_complete_path(path, extractDir, attr->name);
    
    err = recursive_create_parent_dirs(path);
    if (err != PPE_ERR_SUCCESS) {
        return err;
    }

    tempFileHandle = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (tempFileHandle == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    while (fileSize > 0) {
        needLen = (fileSize < WRITE_BUF_SIZE ? fileSize : WRITE_BUF_SIZE);
        
        err = pak_read(ctx, writeBuf, needLen, &readLen);
        if (err != PPE_ERR_SUCCESS) {
            CloseHandle(tempFileHandle);
            return err;
        }

        decode_bytes(writeBuf, writeBuf, readLen);

        if (!WriteFile(tempFileHandle, writeBuf, readLen, NULL, NULL)) {
            err = GetLastError();
            CloseHandle(tempFileHandle);
            return err;
        }

        fileSize -= readLen;
    }

    if (!SetFileTime(tempFileHandle, NULL, NULL, &(attr->lastWriteTime))) {
        err = GetLastError();
        CloseHandle(tempFileHandle);
        return err;
    }

    CloseHandle(tempFileHandle);
    return PPE_ERR_SUCCESS;
}

const char* ppe_errmsg(int code) {
    if (code == PPE_ERR_SUCCESS) {
        return "success";
    }
    else if (code > 0) {
        return win_strerr(code);
    }
    else {
        if (code == PPE_ERR_OUT_OF_MEMORY) {
            return "out of memory";
        }
        else if (code == PPE_ERR_FILE_BROKEN) {
            return "file maybe broken";
        }
        else if (code == PPE_ERR_INVALID_MAGIC) {
            return "invalid .pak magic part";
        }
        else if (code == PPE_ERR_INVALID_VERSION) {
            return "invalid .pak version part";
        }
        else {
            return "unknown error";
        }
    }
}

int ppe_init_context(struct PPE_Context* ctx, const char* pakFilePath) {
    int err;

    ctx->pakHandle = CreateFile(pakFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ctx->pakHandle == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    ctx->pakFileSize = GetFileSize(ctx->pakHandle, NULL);
    if (ctx->pakFileSize == INVALID_FILE_SIZE) {
        err = GetLastError();
        CloseHandle(ctx->pakHandle);
        return err;
    }

    ctx->attrList = create_file_attr_list();
    if (ctx->attrList == NULL) {
        CloseHandle(ctx->pakHandle);
        return PPE_ERR_OUT_OF_MEMORY;
    }

    return PPE_ERR_SUCCESS;
}

void ppe_destory_context(struct PPE_Context* ctx) {
    if (ctx->attrList) {
        destroy_file_attr_list(ctx->attrList);
    }

    if (ctx->pakHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->pakHandle);
    }
}

int ppe_parse_header(struct PPE_Context* ctx) {
    int err;

    err = pak_parse_magic(ctx);
    if (err != PPE_ERR_SUCCESS) {
        return err;
    }

    err = pak_parse_version(ctx);
    if (err != PPE_ERR_SUCCESS) {
        return err;
    }

    err = pak_parse_all_file_attrs(ctx);
    if (err != PPE_ERR_SUCCESS) {
        return err;
    }

    return PPE_ERR_SUCCESS;
}

int ppe_parse_body(struct PPE_Context* ctx, const char* dir) {
    int err;
    struct PPE_FileAttr* cursor = ctx->attrList->head->next;

    while (cursor) {
        err = pak_parse_single_file_body(ctx, cursor, dir);
        if (err != PPE_ERR_SUCCESS) {
            return err;
        }

        cursor = cursor->next;
    }

    return PPE_ERR_SUCCESS;
}
