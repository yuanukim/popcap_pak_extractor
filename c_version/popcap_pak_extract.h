#ifndef __POPCAP_PAK_EXTRACT_H__
#define __POPCAP_PAK_EXTRACT_H__

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* 
    error codes.

    0 means success, else means error.
    negative part are given below, and positive part are for operating systems.

    call str_error() to get the associated error message.
 */
#define  PPE_ERR_SUCCESS           0
#define  PPE_ERR_OUT_OF_MEMORY    -1
#define  PPE_ERR_FILE_BROKEN      -2
#define  PPE_ERR_INVALID_MAGIC    -3
#define  PPE_ERR_INVALID_VERSION  -4

#define PPE_BYTES_OF_MAGIC       4
#define PPE_BYTES_OF_VERSION     4
#define PPE_BYTES_OF_FILE_SIZE   4
#define PPE_BYTES_OF_FILE_TIME   ((UINT32)sizeof(FILETIME))

struct PPE_FileAttr {
    char* name;
    UINT32 size;
    FILETIME lastWriteTime;

    struct PPE_FileAttr* next;
};

struct PPE_FileAttrList {
    struct PPE_FileAttr* head;
    struct PPE_FileAttr* tail;
    UINT32 length;
};

struct PPE_Context {
    UCHAR endFlag;
    UCHAR magic[PPE_BYTES_OF_MAGIC];
    UCHAR version[PPE_BYTES_OF_VERSION];
    HANDLE pakHandle;
    DWORD pakFileSize;
    struct PPE_FileAttrList* attrList;
};

/* format the given error code. */
const char* ppe_errmsg(int code);

/* init context. 
    if success, return PPE_ERR_SUCCESS, else return a error code. */
int ppe_init_context(struct PPE_Context* ctx, const char* pakFilePath);

/* destory context. */
void ppe_destory_context(struct PPE_Context* ctx);

/* try parse the header part. 
    if success, return PPE_ERR_SUCCESS, else return a error code. */
int ppe_parse_header(struct PPE_Context* ctx);

/* try parse the body part and build files into the given dir. 
    if success, return PPE_ERR_SUCCESS, else return a error code */
int ppe_parse_body(struct PPE_Context* ctx, const char* dir);

#endif