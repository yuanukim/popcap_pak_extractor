/*
    @author yuanukim
    @brief popcap's .pak file extractor written in C99, no 3rd parties, only works for windows platform.
    
    a very big thanks to https://github.com/nathaniel-daniel/popcap-pak-rs for giving 
    the popcap .pak file's format:
    
        Header 
        4 bytes - Magic (Should be [0xc0, 0x4a, 0xc0, 0xba])
        4 bytes - Version (Should be all 0) 
        loop 
            1 byte  - Record Flag (exit loop if 0x80)
            1 byte  - File name length (N) 
            N bytes - Filename 
            4 bytes - Filesize (u32)
            4 bytes - Last write time (Microsoft FILETIME struct)
        end
        
        Body
        for each record
            record.filesize bytes - File data
        end
*/
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#define BYTES_OF_MAGIC       4
#define BYTES_OF_VERSION     4
#define BYTES_OF_FILE_SIZE   4
#define BYTES_OF_FILE_TIME   sizeof(FILETIME)

typedef struct FileAttr {
    char* fileName;
    int32_t fileSize;   /* here, must using 4 bytes integer. */
    FILETIME lastWriteTime;
    
    struct FileAttr* next;
} FileAttr;

typedef struct FileAttrList {
    FileAttr* head;
    FileAttr* tail;
    
    int32_t length;
} FileAttrList;

typedef struct PakHeader {
    UCHAR magic[BYTES_OF_MAGIC];
    UCHAR version[BYTES_OF_VERSION];
    
    FileAttrList* attrList;
} PakHeader;

typedef struct WinFile {
    HANDLE hFile;
    DWORD size;
} WinFile;

/*
    compile with -D ENABLE_PPE_ASSERT to let it work at the development/test stage. 
*/
#ifdef ENABLE_PPE_ASSERT
    #define PPE_ASSERT(condition) do { \
        if (!(condition)) { \
            fprintf(stderr, "[%s|%s|%d] assert failed: %s\n", __FILE__, __func__, __LINE__, #condition); \
            abort(); \
        } \
    } while(0)
#else 
    #define PPE_ASSERT(condition) \
        ((void)0)
#endif

/*
    just do what malloc() do, but if malloc() failed, then abort the whole program, and log something.
*/
void* malloc_or_abort(size_t size, const char* fileName, const char* funcName, int lineNumber) {
    PPE_ASSERT(size != 0);
    PPE_ASSERT(fileName != NULL);
    PPE_ASSERT(funcName != NULL);
    PPE_ASSERT(lineNumber >= 0);
    
    void* memory = malloc(size);
    
    if (memory == NULL) {
        fprintf(stderr, "[%s|%s|%d] memory allocated %lld bytes failed.\n", fileName, funcName, lineNumber, size);
        fflush(stderr);
        fflush(stdout);
        abort();
    }
    
    return memory;
}

/*
    This macro will record the position by itself when malloc fails.
*/
#define MALLOC_OR_ABORT(size) \
    malloc_or_abort(size, __FILE__, __func__, __LINE__)

/*
    using windows api to format error code into a human readable message.
    if this function format failed inside, then return a empty string.
    
    This function is not thread safe.
*/
const char* format_windows_error_code(DWORD errCode) {
    static char winErrMsg[1024];
    
    DWORD success = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                             NULL, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)winErrMsg, sizeof(winErrMsg) / sizeof(char), NULL);
                             
    if (success == 0) {
        return "";
    }
    
    return winErrMsg;
}

PakHeader* create_pak_header(void) {
    PakHeader* ph = (PakHeader*)MALLOC_OR_ABORT(sizeof(PakHeader));
    
    memset(&(ph->magic), 0, sizeof(ph->magic));
    memset(&(ph->version), 0, sizeof(ph->version));
    
    ph->attrList = (FileAttrList*)MALLOC_OR_ABORT(sizeof(FileAttrList));
    ph->attrList->length = 0;
    
    ph->attrList->head = (FileAttr*)MALLOC_OR_ABORT(sizeof(FileAttr));
    ph->attrList->head->next = NULL;
    ph->attrList->tail = ph->attrList->head;
    
    return ph;
}

void destroy_pak_header(PakHeader* ph) {
    if (ph) {
        FileAttr* cursor = ph->attrList->head->next;
        FileAttr* temp;

        while (cursor != NULL) {
            temp = cursor;
            cursor = cursor->next;

            free(temp->fileName);
            free(temp);
        }

        free(ph->attrList->head);
        free(ph->attrList);
        free(ph);
    }
}

void pak_header_add_attr(PakHeader* ph, FileAttr* attr) {
    PPE_ASSERT(ph != NULL);
    PPE_ASSERT(attr != NULL);
    
    attr->next = NULL;
    ph->attrList->tail->next = attr;
    ph->attrList->tail = ph->attrList->tail->next;
    ph->attrList->length += 1;
}

WinFile* open_pak_file(const char* path) {
    PPE_ASSERT(path != NULL);
    
    HANDLE hFile = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        fprintf(stderr, "can't open %s, CreateFile() failed: %ld, %s\n", path, err, format_windows_error_code(err));
        exit(EXIT_FAILURE);
    }
    
    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE) {
        DWORD err = GetLastError();
        fprintf(stderr, "can't open %s, GetFileSize() failed: %ld, %s\n", path, err, format_windows_error_code(err));
        exit(EXIT_FAILURE);
    }
    
    WinFile* wf = (WinFile*)MALLOC_OR_ABORT(sizeof(WinFile));
    wf->hFile = hFile;
    wf->size = size;
    
    return wf;
}

void close_pak_file(WinFile* wf) {
    if (wf) {
        CloseHandle(wf->hFile);
        free(wf);
    }
}

void read_pak_file(WinFile* wf, char* buf, DWORD numOfBytesToRead, LPDWORD numOfBytesRead) {
    PPE_ASSERT(wf != NULL);
    PPE_ASSERT(buf != NULL);
    PPE_ASSERT(numOfBytesRead != NULL);
    
    if (wf->size < numOfBytesToRead) {
        fprintf(stderr, "read from .pak failed, this file maybe broken.\n");
        exit(EXIT_FAILURE);
    }

    DWORD _numOfBytesRead;
    if (!ReadFile(wf->hFile, (LPVOID)buf, numOfBytesToRead, &_numOfBytesRead, NULL)) {
        DWORD err = GetLastError();
        fprintf(stderr, "read from .pak failed, ReadFile() failed: %ld, %s\n", err, format_windows_error_code(err));
        exit(EXIT_FAILURE);
    }
    
    if (numOfBytesRead != NULL) {
        *numOfBytesRead = _numOfBytesRead;
    }
}

#define decode_one_byte(ch) \
    (UCHAR)((ch) ^ 0xf7)

#define decode_bytes(fromBuf, toBuf, length) do { \
    int32_t i; \
    for (i = 0; i < (length); ++i) { \
        toBuf[i] = decode_one_byte(fromBuf[i]); \
    } \
} while(0)

bool check_end_flag(UCHAR flag) {
    return flag == 0x80;
}

bool check_magic(const PakHeader* ph) {
    PPE_ASSERT(ph != NULL);
    
    return (ph->magic[0] == 0xc0)
        && (ph->magic[1] == 0x4a)
        && (ph->magic[2] == 0xc0)
        && (ph->magic[3] == 0xba);
}

bool check_version(const PakHeader* ph) {
    PPE_ASSERT(ph != NULL);
    
    return (ph->version[0] == 0x00)
        && (ph->version[1] == 0x00)
        && (ph->version[2] == 0x00)
        && (ph->version[3] == 0x00);
}

UCHAR parse_end_flag(WinFile* wf) {
    PPE_ASSERT(wf != NULL);
    
    UCHAR flag;
    read_pak_file(wf, (char*)&flag, sizeof(UCHAR), NULL);
    return decode_one_byte(flag);
}

void parse_magic(PakHeader* ph, WinFile* wf) {
    PPE_ASSERT(ph != NULL);
    PPE_ASSERT(wf != NULL);
    
    read_pak_file(wf, (char*)ph->magic, sizeof(ph->magic), NULL);
    decode_bytes(ph->magic, ph->magic, BYTES_OF_MAGIC);
    
    if (!check_magic(ph)) {
        fprintf(stderr, "parse magic failed, this file is not a valid .pak\n");
        exit(EXIT_FAILURE);
    }
}

void parse_version(PakHeader* ph, WinFile* wf) {
    PPE_ASSERT(ph != NULL);
    PPE_ASSERT(wf != NULL);
    
    read_pak_file(wf, (char*)ph->version, sizeof(ph->version), NULL);
    decode_bytes(ph->version, ph->version, BYTES_OF_VERSION);
    
    if (!check_version(ph)) {
        fprintf(stderr, "parse version failed, this file is not a valid .pak\n");
        exit(EXIT_FAILURE);
    }
}

void parse_file_name(PakHeader* ph, WinFile* wf, FileAttr* attr) {
    PPE_ASSERT(ph != NULL);
    PPE_ASSERT(wf != NULL);
    PPE_ASSERT(attr != NULL);
    
    UCHAR byte;
    read_pak_file(wf, (char*)&byte, sizeof(byte), NULL);
    
    int32_t filenameLen = (int32_t)decode_one_byte(byte);
    attr->fileName = (char*)MALLOC_OR_ABORT((filenameLen + 1) * sizeof(char));
    
    read_pak_file(wf, attr->fileName, filenameLen * sizeof(char), NULL);
    decode_bytes(attr->fileName, attr->fileName, filenameLen);
    attr->fileName[filenameLen] = '\0';
}

void parse_file_size(WinFile* wf, FileAttr* attr) {
    PPE_ASSERT(wf != NULL);
    PPE_ASSERT(attr != NULL);
    
    UCHAR* buf = (UCHAR*)(&(attr->fileSize));
    
    read_pak_file(wf, (char*)buf, sizeof(attr->fileSize), NULL);
    decode_bytes(buf, buf, BYTES_OF_FILE_SIZE);
}

void parse_file_last_write_time(PakHeader* ph, WinFile* wf, FileAttr* attr) {
    PPE_ASSERT(ph != NULL);
    PPE_ASSERT(wf != NULL);
    PPE_ASSERT(attr != NULL);
    
    UCHAR* buf = (UCHAR*)(&(attr->lastWriteTime));

    read_pak_file(wf, (char*)buf, sizeof(attr->lastWriteTime), NULL);
    decode_bytes(buf, buf, (int32_t)BYTES_OF_FILE_TIME);
}

void parse_all_file_attrs(PakHeader* ph, WinFile* wf) {
    PPE_ASSERT(ph != NULL);
    PPE_ASSERT(wf != NULL);
    
    while (true) {
        UCHAR endFlag = parse_end_flag(wf);
        if (check_end_flag(endFlag)) {
            break;
        }
        
        FileAttr* attr = (FileAttr*)MALLOC_OR_ABORT(sizeof(FileAttr));
        
        parse_file_name(ph, wf, attr);
        parse_file_size(wf, attr);
        parse_file_last_write_time(ph, wf, attr);
        pak_header_add_attr(ph, attr);
    }
}

void parse_header(PakHeader* ph, WinFile* wf) {
    PPE_ASSERT(ph != NULL);
    PPE_ASSERT(wf != NULL);
    
    printf("parse magic.\n");
    parse_magic(ph, wf);    
    
    printf("parse version.\n");
    parse_version(ph, wf);
    
    printf("parse all file attributes.\n");
    parse_all_file_attrs(ph, wf);
    
    printf("parse header success, the number of the file attributes is %d.\n", ph->attrList->length);
}

const char* format_windows_filetime_struct(const FILETIME* ft) {
    PPE_ASSERT(ft != NULL);
    
    static char buf[64];
    
    ULARGE_INTEGER ull;
    ull.LowPart = ft->dwLowDateTime;
    ull.HighPart = ft->dwHighDateTime;

    /* 
        windows file time begins from 1601/01/01, but unix timestamp 
        begins from 1970/01/01, so we have to minus this duration, 
        that's where 11644473600LL seconds come from.
        
        uli.QuadPart accurates to 10 ^ -7 seconds.
    */
    time_t timestamp = (time_t)((ull.QuadPart / 10000000ULL) - 11644473600ULL);
    struct tm *timeinfo = localtime(&timestamp);
    strftime(buf, sizeof(buf) / sizeof(char), "%Y-%m-%d %H:%M:%S", timeinfo);
    return buf;
}

void save_file_attr_list(PakHeader* ph) {
    PPE_ASSERT(ph != NULL);
    
    printf("save file attributes.\n");
    
    const char* savPath = "popcap_pak_extractor_file_attr_list.txt";
    FILE* savFile = fopen(savPath, "w");
    if (savFile == NULL) {
        fprintf(stderr, "can't save file attribute list to \"%s\"\n", savPath);
        return;
    }

    const FileAttr* cursor = ph->attrList->head->next;

    while (cursor != NULL) {
        const char* lastWriteTime = format_windows_filetime_struct(&(cursor->lastWriteTime));
        fprintf(savFile, "%s, %10d bytes, %s\n", lastWriteTime, cursor->fileSize, cursor->fileName);
        cursor = cursor->next;
    }

    fclose(savFile);
    printf("save file attributes to file \"%s\" success.\n", savPath);
}

void build_complete_path(char* buf, const char* extractPath, const char* fileName) {
    PPE_ASSERT(buf != NULL);
    PPE_ASSERT(extractPath != NULL);
    PPE_ASSERT(fileName != NULL);
    
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

bool is_dir_exist(const char* path) {
    PPE_ASSERT(path != NULL);
    
    DWORD dwAttrib = GetFileAttributes(path);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES 
        && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

void recursive_create_parent_dirs(char* path) {
    PPE_ASSERT(path != NULL);
    
    char* cursor = path;

    while (*cursor != '\0') {
        if (*cursor == '\\') {
            /* split a substr here, just make it ends with '\0'. */
            *cursor = '\0';

            if (!is_dir_exist(path)) {
                if (!CreateDirectory(path, NULL)) {
                    DWORD err = GetLastError();
                    fprintf(stderr, "can't create dir: %s, CreateDirectory() failed: %ld, %s\n", path, err, format_windows_error_code(err));
                    exit(EXIT_FAILURE);
                }
            }

            /* setting back. */
            *cursor = '\\';
        }

        ++cursor;
    }
}

void save_single_file_data(const FileAttr* attr, WinFile* wf, HANDLE hFile, char* buf, int32_t bufLen) {
    PPE_ASSERT(attr != NULL);
    PPE_ASSERT(wf != NULL);
    PPE_ASSERT(hFile != INVALID_HANDLE_VALUE);
    PPE_ASSERT(buf != NULL);
    
    int32_t fileSize = attr->fileSize;
    int32_t needLen;
    int32_t readLen;
    DWORD err;
    
    while (fileSize > 0) {
        needLen = (fileSize < bufLen ? fileSize : bufLen);
        
        read_pak_file(wf, buf, needLen * sizeof(char), (LPDWORD)&readLen);
        decode_bytes(buf, buf, readLen);
        
        if (!WriteFile(hFile, buf, readLen, NULL, NULL)) {
            err = GetLastError();
            fprintf(stderr, "save %s data failed, WriteFile() failed: %ld, %s\n", attr->fileName, err, format_windows_error_code(err));
            exit(EXIT_FAILURE);
        }

        fileSize -= readLen;
    }
    
    if (!SetFileTime(hFile, NULL, NULL, &(attr->lastWriteTime))) {
        err = GetLastError();
        fprintf(stderr, "save %s data failed, SetFileTime() failed: %ld, %s\n", attr->fileName, err, format_windows_error_code(err));
        exit(EXIT_FAILURE);
    }
}

void extract_single_file(const FileAttr* attr, WinFile* wf, const char* extractDir, char* buf, int32_t bufLen) {
    PPE_ASSERT(attr != NULL);
    PPE_ASSERT(wf != NULL);
    PPE_ASSERT(extractDir != NULL);
    PPE_ASSERT(buf != NULL);
    
    char path[MAX_PATH];
    build_complete_path(path, extractDir, attr->fileName);
    
    recursive_create_parent_dirs(path);
    
    HANDLE hFile = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        fprintf(stderr, "cannot create %s, CreateFile() failed: %ld, %s\n", path, err, format_windows_error_code(err));
        exit(EXIT_FAILURE);
    }
    
    save_single_file_data(attr, wf, hFile, buf, bufLen);
    CloseHandle(hFile);
}

void extract_inner_files(PakHeader* ph, WinFile* wf, const char* extractDir) {
    PPE_ASSERT(ph != NULL);
    PPE_ASSERT(wf != NULL);
    PPE_ASSERT(extractDir != NULL);
    
    printf("extract inner files.\n");
    
    int32_t buf_size = 65536;
    char* buf = (char*)MALLOC_OR_ABORT(buf_size * sizeof(char));
    
    const FileAttr* cursor = ph->attrList->head->next;
    while (cursor != NULL) {
        extract_single_file(cursor, wf, extractDir, buf, buf_size);
        cursor = cursor->next;
    }
    
    free(buf);
    printf("extract inner files to dir \"%s\" success.\n", extractDir);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s yours.pak savDir\n", argv[0]);
        return 1;
    }
    
    if (is_dir_exist(argv[2])) {
        fprintf(stderr, "given dir: %s is already existed.\n", argv[2]);
        return 1;
    }
    
    WinFile* wf = open_pak_file(argv[1]);
    PakHeader* ph = create_pak_header();
    
    parse_header(ph, wf);
    save_file_attr_list(ph);
    extract_inner_files(ph, wf, argv[2]);
    
    destroy_pak_header(ph);
    close_pak_file(wf);
    return 0;
}
