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

FileAttr* create_file_attr(void) {
    FileAttr* attr = (FileAttr*)malloc(sizeof(FileAttr));
    
    if (attr == NULL) {
        fprintf(stderr, "[ERROR] %s: no enough memory to hold a FileAttr object\n", __func__);
        return NULL;
    }
    
    attr->fileName = NULL;
    attr->next = NULL;
    return attr;
}

void destroy_file_attr(FileAttr* attr) {
    if (attr) {
        if (attr->fileName) {
            free(attr->fileName);
        }
        
        free(attr);
    }
}

PakHeader* create_pak_header(void) {
    PakHeader* ph = (PakHeader*)malloc(sizeof(PakHeader));
    if (ph == NULL) {
        fprintf(stderr, "[ERROR] %s: no enough memory to create a PakHeader object\n", __func__);
        return NULL;
    }
    
    memset(&(ph->magic), 0, sizeof(ph->magic));
    memset(&(ph->version), 0, sizeof(ph->version));
    
    ph->attrList = (FileAttrList*)malloc(sizeof(FileAttrList));
    if (ph->attrList == NULL) {
        fprintf(stderr, "[ERROR] %s: no enough memory to create a attrList\n", __func__);
        goto err_clean_pak_header;
    }
    
    ph->attrList->length = 0;
    
    ph->attrList->head = (FileAttr*)malloc(sizeof(FileAttr));
    if (ph->attrList->head == NULL) {
        fprintf(stderr, "[ERROR] %s: no enough memory to create a attrList head\n", __func__);
        goto err_clean_attr_list;
    }
    
    ph->attrList->head->next = NULL;
    ph->attrList->tail = ph->attrList->head;
    return ph;
    
err_clean_attr_list:
    free(ph->attrList);
err_clean_pak_header:
    free(ph);

    return NULL;
}

void destroy_pak_header(PakHeader* ph) {
    if (ph) {
        FileAttr* cursor = ph->attrList->head->next;
        FileAttr* temp;

        while (cursor != NULL) {
            temp = cursor;
            cursor = cursor->next;

            destroy_file_attr(temp);
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
        fprintf(stderr, "[ERROR] %s: cannot get the file handle of \"%s\": %ld, %s\n", __func__, path, err, format_windows_error_code(err));
        return NULL;
    }
    
    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE) {
        DWORD err = GetLastError();
        fprintf(stderr, "[ERROR] %s: cannot get file size of \"%s\": %ld, %s\n", __func__, path, err, format_windows_error_code(err));
        goto err_clean_file;
    }
    
    WinFile* wf = (WinFile*)malloc(sizeof(WinFile));
    if (wf == NULL) {
        fprintf(stderr, "[ERROR] %s: no enough memory to create a WinFile object on \"%s\"\n", __func__, path);
        goto err_clean_file;
    }
    
    wf->hFile = hFile;
    wf->size = size;
    
    return wf;
    
err_clean_file:
    CloseHandle(hFile);
    
    return NULL;
}

void close_pak_file(WinFile* wf) {
    if (wf) {
        CloseHandle(wf->hFile);
        free(wf);
    }
}

bool read_pak_file(WinFile* wf, char* buf, DWORD numOfBytesToRead, LPDWORD numOfBytesRead) {
    PPE_ASSERT(wf != NULL);
    PPE_ASSERT(buf != NULL);
    PPE_ASSERT(numOfBytesRead != NULL);
    
    if (wf->size < numOfBytesToRead) {
        fprintf(stderr, "[ERROR] %s: remaing file size is less than required %ld bytes, .pak file maybe broken\n", __func__, numOfBytesToRead);
        return false;
    }

    DWORD temp;
    if (!ReadFile(wf->hFile, (LPVOID)buf, numOfBytesToRead, &temp, NULL)) {
        DWORD err = GetLastError();
        fprintf(stderr, "[ERROR] %s: cannot read from file to get %ld bytes: %ld, %s\n", __func__, numOfBytesToRead, err, format_windows_error_code(err));
        return false;
    }
    
    wf->size -= temp;
    
    if (numOfBytesRead != NULL) {
        *numOfBytesRead = temp;
    }
    
    return true;
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

bool parse_end_flag(WinFile* wf, UCHAR* endFlag) {
    PPE_ASSERT(wf != NULL);
    PPE_ASSERT(endFlag != NULL);
    
    if (!read_pak_file(wf, (char*)endFlag, sizeof(UCHAR), NULL)) {
        fprintf(stderr, "[ERROR] %s: cannot read from the .pak file\n", __func__);
        return false;
    }
    
    *endFlag = decode_one_byte(*endFlag);
    return true;
}

bool parse_magic(PakHeader* ph, WinFile* wf) {
    PPE_ASSERT(ph != NULL);
    PPE_ASSERT(wf != NULL);
    
    if (!read_pak_file(wf, (char*)ph->magic, sizeof(ph->magic), NULL)) {
        fprintf(stderr, "[ERROR] %s: cannot read from the .pak file\n", __func__);
        return false;
    }
    
    decode_bytes(ph->magic, ph->magic, BYTES_OF_MAGIC);
    return true;
}

bool parse_version(PakHeader* ph, WinFile* wf) {
    PPE_ASSERT(ph != NULL);
    PPE_ASSERT(wf != NULL);
    
    if (!read_pak_file(wf, (char*)ph->version, sizeof(ph->version), NULL)) {
        fprintf(stderr, "[ERROR] %s: cannot read from the .pak file\n", __func__);
        return false;
    }
    
    decode_bytes(ph->version, ph->version, BYTES_OF_VERSION);
    return true;
}

bool parse_file_name(WinFile* wf, FileAttr* attr) {
    PPE_ASSERT(wf != NULL);
    PPE_ASSERT(attr != NULL);
    
    UCHAR byte;
    if (!read_pak_file(wf, (char*)&byte, sizeof(byte), NULL)) {
        fprintf(stderr, "[ERROR] %s: cannot read from the .pak file, get file name length failed\n", __func__);
        return false;
    }
    
    int32_t filenameLen = (int32_t)decode_one_byte(byte);
    attr->fileName = (char*)malloc((filenameLen + 1) * sizeof(char));
    if (attr->fileName == NULL) {
        fprintf(stderr, "[ERROR] %s: no enough memory to hold filename\n", __func__);
        return false;
    }
    
    if (!read_pak_file(wf, attr->fileName, filenameLen * sizeof(char), NULL)) {
        fprintf(stderr, "[ERROR] %s: cannot read from the .pak file, get filename failed\n", __func__);
        
        free(attr->fileName);
        attr->fileName = NULL;
        return false;
    }
    
    decode_bytes(attr->fileName, attr->fileName, filenameLen);
    attr->fileName[filenameLen] = '\0';
    return true;
}

bool parse_file_size(WinFile* wf, FileAttr* attr) {
    PPE_ASSERT(wf != NULL);
    PPE_ASSERT(attr != NULL);
    
    UCHAR* buf = (UCHAR*)(&(attr->fileSize));
    
    if (!read_pak_file(wf, (char*)buf, sizeof(attr->fileSize), NULL)) {
        fprintf(stderr, "[ERROR] %s: cannot read from the .pak file, get file size failed\n", __func__);
        return false;
    }
    
    decode_bytes(buf, buf, BYTES_OF_FILE_SIZE);
    return true;
}

bool parse_file_last_write_time(WinFile* wf, FileAttr* attr) {
    PPE_ASSERT(wf != NULL);
    PPE_ASSERT(attr != NULL);
    
    UCHAR* buf = (UCHAR*)(&(attr->lastWriteTime));

    if (!read_pak_file(wf, (char*)buf, sizeof(attr->lastWriteTime), NULL)) {
        fprintf(stderr, "[ERROR] %s: cannot read from the .pak file, get file last write time failed\n", __func__);
        return false;
    }
    
    decode_bytes(buf, buf, (int32_t)BYTES_OF_FILE_TIME);
    return true;
}

bool parse_all_file_attrs(PakHeader* ph, WinFile* wf) {
    PPE_ASSERT(ph != NULL);
    PPE_ASSERT(wf != NULL);
    
    FileAttr* attr;
    
    while (true) {
        UCHAR endFlag;
        
        if (!parse_end_flag(wf, &endFlag)) {
            fprintf(stderr, "[ERROR] %s: parse end flag of the header failed\n", __func__);
            return false;
        }
        
        if (check_end_flag(endFlag)) {
            break;
        }
        
        attr = create_file_attr();
        if (attr == NULL) {
            fprintf(stderr, "[ERROR] %s: cannot create a FileAttr object\n", __func__);
            return false;
        }
        
        if (!parse_file_name(wf, attr)) {
            fprintf(stderr, "[ERROR] %s: parse one file name failed\n", __func__);
            goto meets_error;
        }
        
        if (!parse_file_size(wf, attr)) {
            fprintf(stderr, "[ERROR] %s: parse one file size failed on \"%s\"\n", __func__, attr->fileName);
            goto meets_error;
        }
        
        if (!parse_file_last_write_time(wf, attr)) {
            fprintf(stderr, "[ERROR] %s: parse one file last write time failed on \"%s\"\n", __func__, attr->fileName);
            goto meets_error;
        }
        
        pak_header_add_attr(ph, attr);
    }
    
    return true;
    
meets_error:
    destroy_file_attr(attr);
    return false;
}

bool parse_header(PakHeader* ph, WinFile* wf) {
    PPE_ASSERT(ph != NULL);
    PPE_ASSERT(wf != NULL);
    
    printf("[INFO] parse magic\n");
    if (!parse_magic(ph, wf)) {
        fprintf(stderr, "[ERROR] %s: parse magic failed\n", __func__);
        return false;
    }
    
    if (!check_magic(ph)) {
        fprintf(stderr, "[ERROR] %s: check magic failed\n", __func__);
        return false;
    }
    
    printf("[INFO] parse version\n");
    if (!parse_version(ph, wf)) {
        fprintf(stderr, "[ERROR] %s: parse version failed\n", __func__);
        return false;
    }
    
    if (!check_version(ph)) {
        fprintf(stderr, "[ERROR] %s: check version failed\n", __func__);
        return false;
    }
    
    printf("[INFO] parse all file attributes\n");
    if (!parse_all_file_attrs(ph, wf)) {
        fprintf(stderr, "[ERROR] %s: parse all file attributes failed\n", __func__);
        return false;
    }
    
    printf("[INFO] parse header success, the number of the file attributes is %d\n", ph->attrList->length);
    return true;
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
    
    printf("[INFO] save file attributes\n");
    
    const char* savPath = "pak_file_attributes.txt";
    FILE* savFile = fopen(savPath, "w");
    if (savFile == NULL) {
        fprintf(stderr, "[ERROR] %s: cannot save file attributes to \"%s\"\n", __func__, savPath);
        return;
    }

    const FileAttr* cursor = ph->attrList->head->next;

    while (cursor != NULL) {
        const char* lastWriteTime = format_windows_filetime_struct(&(cursor->lastWriteTime));
        fprintf(savFile, "%s, %10d bytes, %s\n", lastWriteTime, cursor->fileSize, cursor->fileName);
        cursor = cursor->next;
    }

    fclose(savFile);
    printf("[INFO] save file attributes to file \"%s\" success\n", savPath);
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

bool recursive_create_parent_dirs(char* path) {
    PPE_ASSERT(path != NULL);
    
    char* cursor = path;

    while (*cursor != '\0') {
        if (*cursor == '\\') {
            /* split a substr here, just make it ends with '\0'. */
            *cursor = '\0';

            if (!is_dir_exist(path)) {
                if (!CreateDirectory(path, NULL)) {
                    DWORD err = GetLastError();
                    fprintf(stderr, "[ERROR] %s: can't create dir: \"%s\", CreateDirectory() failed: %ld, %s\n", __func__, path, err, format_windows_error_code(err));
                    return false;
                }
            }

            /* setting back. */
            *cursor = '\\';
        }

        ++cursor;
    }
    
    return true;
}

bool save_single_file_data(const FileAttr* attr, WinFile* wf, HANDLE hFile, char* buf, int32_t bufLen) {
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
        
        if (!read_pak_file(wf, buf, needLen * sizeof(char), (LPDWORD)&readLen)) {
            fprintf(stderr, "[ERROR] %s: cannot read from \"%s\"\n", __func__, attr->fileName);
            return false;
        }
        
        decode_bytes(buf, buf, readLen);
        
        if (!WriteFile(hFile, buf, readLen, NULL, NULL)) {
            err = GetLastError();
            fprintf(stderr, "[ERROR] %s: cannot write to \"%s\": %ld, %s\n", __func__, attr->fileName, err, format_windows_error_code(err));
            return false;
        }

        fileSize -= readLen;
    }
    
    if (!SetFileTime(hFile, NULL, NULL, &(attr->lastWriteTime))) {
        err = GetLastError();
        fprintf(stderr, "[ERROR] %s: cannot set the last write time to \"%s\": %ld, %s\n", __func__, attr->fileName, err, format_windows_error_code(err));
        return false;
    }
    
    return true;
}

bool extract_single_file(const FileAttr* attr, WinFile* wf, const char* extractDir, char* buf, int32_t bufLen) {
    PPE_ASSERT(attr != NULL);
    PPE_ASSERT(wf != NULL);
    PPE_ASSERT(extractDir != NULL);
    PPE_ASSERT(buf != NULL);
    
    char path[MAX_PATH];
    build_complete_path(path, extractDir, attr->fileName);
    
    if (!recursive_create_parent_dirs(path)) {
        fprintf(stderr, "[ERROR] %s: cannot create parent dir of \"%s\"\n", __func__, attr->fileName);
        return false;
    }
    
    HANDLE hFile = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        fprintf(stderr, "[ERROR] %s: cannot create a file named \"%s\": %ld, %s\n", __func__, path, err, format_windows_error_code(err));
        return false;
    }
    
    if (!save_single_file_data(attr, wf, hFile, buf, bufLen)) {
        fprintf(stderr, "[ERROR] %s: save the data of \"%s\" failed\n", __func__, attr->fileName);
        CloseHandle(hFile);
        return false;
    }
    
    CloseHandle(hFile);
    return true;
}

bool extract_inner_files(PakHeader* ph, WinFile* wf, const char* extractDir) {
    PPE_ASSERT(ph != NULL);
    PPE_ASSERT(wf != NULL);
    PPE_ASSERT(extractDir != NULL);
    
    printf("[INFO] extract inner files\n");
    
    int32_t buf_size = 65536;
    char* buf = (char*)malloc(buf_size * sizeof(char));
    if (buf == NULL) {
        fprintf(stderr, "[ERROR] %s: no enough memory to create a read buffer\n", __func__);
        return false;
    }
    
    const FileAttr* cursor = ph->attrList->head->next;
    while (cursor != NULL) {
        if (!extract_single_file(cursor, wf, extractDir, buf, buf_size)) {
            fprintf(stderr, "[ERROR] %s: extract the data of \"%s\" failed\n", __func__, cursor->fileName);
            free(buf);
            return false;
        }
        
        cursor = cursor->next;
    }
    
    free(buf);
    printf("[INFO] extract inner files to dir \"%s\" success\n", extractDir);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s yours.pak savDir\n", argv[0]);
        return 1;
    }
    
    if (is_dir_exist(argv[2])) {
        fprintf(stderr, "[ERROR] given dir: \"%s\" is already existed\n", argv[2]);
        return 1;
    }
    
    WinFile* wf = open_pak_file(argv[1]);
    if (wf == NULL) {
        fprintf(stderr, "[ERROR] cannot open \"%s\" as a valid .pak file, stop\n", argv[1]);
        return 1;
    }
    
    PakHeader* ph = create_pak_header();
    if (ph == NULL) {
        fprintf(stderr, "[ERROR] cannot create a .pak header object, stop\n");
        goto final_clean_pak_file;
    }
    
    if (!parse_header(ph, wf)) {
        fprintf(stderr, "[ERROR] process meets error, stop\n");
        goto final_clean_pak_header;
    }
    
    save_file_attr_list(ph);
    
    if (!extract_inner_files(ph, wf, argv[2])) {
        fprintf(stderr, "[ERROR] process meets error, stop\n");
        goto final_clean_pak_header;
    }
    
final_clean_pak_header:
    destroy_pak_header(ph);
final_clean_pak_file:
    close_pak_file(wf);
    
    return 0;
}
