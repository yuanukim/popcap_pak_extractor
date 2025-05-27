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
#include <stdarg.h>
#include <string.h>
#include <time.h>

#define BYTES_OF_MAGIC       4
#define BYTES_OF_VERSION     4
#define BYTES_OF_FILE_SIZE   4
#define BYTES_OF_FILE_TIME   ((int32_t)sizeof(FILETIME))

typedef struct FileAttr {
    char* name;
    int32_t size;
    FILETIME lastWriteTime;
    
    struct FileAttr* next;
} FileAttr;

typedef struct FileAttrList {
    FileAttr* head;
    FileAttr* tail;
    
    int32_t length;
} FileAttrList;

typedef struct WinFile {
    HANDLE handle;
    DWORD size;
} WinFile;

typedef struct Extractor {
    UCHAR magic[BYTES_OF_MAGIC];
    UCHAR version[BYTES_OF_VERSION];
    
    FileAttrList* attrList;
    WinFile* pakFile;
} Extractor;

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

/*
    log error, this function will add '\n' automatically.
*/
void log_error(const char* fmt, ...) {
    va_list args;
    
    fprintf(stderr, "[ERROR] ");
    
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    fprintf(stderr, "\n");
}

/*
    log windows error, this function will add '\n' automatically.
*/
void log_win_error(DWORD errCode, const char* fmt, ...) {
    va_list args;
    
    fprintf(stderr, "[ERROR] ");
    
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    fprintf(stderr, ", %ld, %s\n", errCode, format_windows_error_code(errCode));
}

FileAttr* create_file_attr(void) {
    FileAttr* attr = (FileAttr*)malloc(sizeof(FileAttr));
    if (attr == NULL) {
        log_error("%s, %d: malloc failed", __func__, __LINE__);
        return NULL;
    }
    
    attr->name = NULL;
    attr->next = NULL;
    return attr;
}

void destroy_file_attr(FileAttr* attr) {
    if (attr) {
        free(attr->name);
        free(attr);
    }
}

FileAttrList* create_file_attr_list(void) {
    FileAttrList* list = (FileAttrList*)malloc(sizeof(FileAttrList));
    if (list == NULL) {
        log_error("%s, %d: malloc failed to create FileAttrList object", __func__, __LINE__);
        return NULL;
    }
    
    list->head = (FileAttr*)malloc(sizeof(FileAttr));
    if (list->head == NULL) {
        log_error("%s, %d: malloc failed to create FileAttr object", __func__, __LINE__);
        free(list);
        return NULL;
    }
    
    list->head->next = NULL;
    list->tail = list->head;
    list->length = 0;
    return list;
}

void destroy_file_attr_list(FileAttrList* list) {
    if (list) {
        FileAttr* cursor = list->head->next;
        FileAttr* temp;

        while (cursor != NULL) {
            temp = cursor;
            cursor = cursor->next;

            destroy_file_attr(temp);
        }

        free(list->head);
        free(list);
    }
}

void file_attr_list_add(FileAttrList* list, FileAttr* attr) {
    attr->next = NULL;
    
    list->tail->next = attr;
    list->tail = list->tail->next;
    list->length += 1;
}

WinFile* create_win_file(const char* path) {
    HANDLE h = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        log_win_error(err, "%s, %d: CreateFile failed on \"%s\"", __func__, __LINE__, path);
        return NULL;
    }
    
    DWORD size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE) {
        DWORD err = GetLastError();
        log_win_error(err, "%s, %d: GetFileSize failed on \"%s\"", __func__, __LINE__, path);
        CloseHandle(h);
        return NULL;
    }
    
    WinFile* wf = (WinFile*)malloc(sizeof(WinFile));
    if (wf == NULL) {
        log_error("%s, %d: malloc failed", __func__, __LINE__);
        CloseHandle(h);
        return NULL;
    }
    
    wf->handle = h;
    wf->size = size;
    return wf;
}

void destroy_win_file(WinFile* wf) {
    if (wf) {
        if (wf->handle != INVALID_HANDLE_VALUE) {
            CloseHandle(wf->handle);
        }
        
        free(wf);
    }
}

/*
    read from the WinFile object.
    return INVALID_FILE_SIZE means error, else return the read length.
*/
bool win_file_read(WinFile* wf, char* buf, DWORD numOfBytesToRead, DWORD* readLen) {
    if (wf->size < numOfBytesToRead) {
        log_error("%s, %d: remained file size is less than required, file maybe broken", __func__, __LINE__);
        return false;
    }
    
    DWORD temp;
    if (!ReadFile(wf->handle, (LPVOID)buf, numOfBytesToRead, &temp, NULL)) {
        DWORD err = GetLastError();
        log_win_error(err, "%s, %d: ReadFile failed", __func__, __LINE__);
        return false;
    }
    
    wf->size -= temp;
    
    if (readLen != NULL) {
        *readLen = temp;
    }
    
    return true;
}

Extractor* create_extractor(const char* path) {
    Extractor* ext = (Extractor*)malloc(sizeof(Extractor));
    if (ext == NULL) {
        log_error("%s, %d: malloc failed", __func__, __LINE__);
        return NULL;
    }
    
    ext->attrList = create_file_attr_list();
    if (ext->attrList == NULL) {
        log_error("%s, %d: create_file_attr_list failed", __func__, __LINE__);
        free(ext);
        return NULL;
    }
    
    ext->pakFile = create_win_file(path);
    if (ext->pakFile == NULL) {
        log_error("%s, %d: create_win_file failed", __func__, __LINE__);
        destroy_file_attr_list(ext->attrList);
        free(ext);
        return NULL;
    }
    
    return ext;
}

void destroy_extractor(Extractor* ext) {
    if (ext) {
        destroy_file_attr_list(ext->attrList);
        destroy_win_file(ext->pakFile);
        free(ext);
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

bool check_magic(Extractor* ext) {
    return (ext->magic[0] == 0xc0)
        && (ext->magic[1] == 0x4a)
        && (ext->magic[2] == 0xc0)
        && (ext->magic[3] == 0xba);
}

bool check_version(Extractor* ext) {
    return (ext->version[0] == 0x00)
        && (ext->version[1] == 0x00)
        && (ext->version[2] == 0x00)
        && (ext->version[3] == 0x00);
}

bool reach_header_end(UCHAR flag) {
    return flag == 0x80;
}

bool parse_header_end_flag(Extractor* ext, UCHAR* flag) {
    UCHAR temp;
    if (!win_file_read(ext->pakFile, (char*)&temp, sizeof(temp), NULL)) {
        log_error("%s, %d: win_file_read failed", __func__, __LINE__);
        return false;
    }
    
    *flag = decode_one_byte(temp);
    return true;
}

bool parse_magic(Extractor* ext) {
    if (!win_file_read(ext->pakFile, (char*)(ext->magic), sizeof(ext->magic), NULL)) {
        log_error("%s, %d: win_file_read failed", __func__, __LINE__);
        return false;
    }
    
    decode_bytes(ext->magic, ext->magic, BYTES_OF_MAGIC);
    return true;
}

bool parse_version(Extractor* ext) {
    if (!win_file_read(ext->pakFile, (char*)(ext->version), sizeof(ext->version), NULL)) {
        log_error("%s, %d: win_file_read failed", __func__, __LINE__);
        return false;
    }
    
    decode_bytes(ext->version, ext->version, BYTES_OF_VERSION);
    return true;
}

bool parse_file_name(Extractor* ext, FileAttr* attr) {
    UCHAR byte;
    if (!win_file_read(ext->pakFile, (char*)&byte, sizeof(byte), NULL)) {
        log_error("%s, %d: win_file_read failed", __func__, __LINE__);
        return false;
    }
    
    int32_t filenameLen = (int32_t)decode_one_byte(byte);
    char* name = (char*)malloc((filenameLen + 1) * sizeof(char));
    if (name == NULL) {
        log_error("%s, %d: malloc failed", __func__, __LINE__);
        return false;
    }
    
    if (!win_file_read(ext->pakFile, name, filenameLen, NULL)) {
        log_error("%s, %d: win_file_read failed", __func__, __LINE__);
        free(name);
        return false;
    }
    
    decode_bytes(name, name, filenameLen);
    name[filenameLen] = '\0';
    attr->name = name;
    return true;
}

bool parse_file_size(Extractor* ext, FileAttr* attr) {
    char* buf = (char*)(&(attr->size));
    
    if (!win_file_read(ext->pakFile, buf, sizeof(attr->size), NULL)) {
        log_error("%s, %d: win_file_read failed", __func__, __LINE__);
        return false;
    }
    
    decode_bytes(buf, buf, BYTES_OF_FILE_SIZE);
    return true;
}

bool parse_file_last_write_time(Extractor* ext, FileAttr* attr) {
    char* buf = (char*)(&(attr->lastWriteTime));
    
    if (!win_file_read(ext->pakFile, buf, sizeof(attr->lastWriteTime), NULL)) {
        log_error("%s, %d: win_file_read failed", __func__, __LINE__);
        return false;
    }
    
    decode_bytes(buf, buf, BYTES_OF_FILE_TIME);
    return true;
}

bool parse_all_file_attrs(Extractor* ext) {
    FileAttr* attr;
    UCHAR flag;
    
    while (true) {
        if (!parse_header_end_flag(ext, &flag)) {
            log_error("%s, %d: parse_header_end_flag failed", __func__, __LINE__);
            return false;
        }
        
        if (reach_header_end(flag)) {
            return true;
        }
        
        attr = create_file_attr();
        
        if (!parse_file_name(ext, attr)) {
            destroy_file_attr(attr);
            log_error("%s, %d: parse_file_name failed", __func__, __LINE__);
            return false;
        }
        
        if (!parse_file_size(ext, attr)) {
            destroy_file_attr(attr);
            log_error("%s, %d: parse_file_size failed", __func__, __LINE__);
            return false;
        }
        
        if (!parse_file_last_write_time(ext, attr)) {
            destroy_file_attr(attr);
            log_error("%s, %d: parse_file_last_write_time failed", __func__, __LINE__);
            return false;
        }
        
        file_attr_list_add(ext->attrList, attr);
    }
}

bool parse_header(Extractor* ext) {
    printf("========= parse header =========\n");
    
    printf("[INFO] parse magic\n");
    
    if (!parse_magic(ext)) {
        log_error("%s, %d: parse_magic failed", __func__, __LINE__);
        return false;
    }
    
    if (!check_magic(ext)) {
        log_error("%s, %d: check_magic failed", __func__, __LINE__);
        return false;
    }
    
    printf("[INFO] parse version\n");
    
    if (!parse_version(ext)) {
        log_error("%s, %d: parse_version failed", __func__, __LINE__);
        return false;
    }
    
    if (!check_version(ext)) {
        log_error("%s, %d: check_version failed", __func__, __LINE__);
        return false;
    }
    
    printf("[INFO] parse all file attributes\n");
    
    if (!parse_all_file_attrs(ext)) {
        log_error("%s, %d: parse_all_file_attrs failed", __func__, __LINE__);
        return false;
    }
    
    printf("[INFO] parse header success, the number of the file attributes is %d\n", ext->attrList->length);
    return true;
}

const char* format_windows_filetime(FILETIME* ft) {
    static char buf[32];
    
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

void save_file_attr_list(Extractor* ext) {
    printf("========= save file attributes =========\n");
    
    const char* savPath = "pak_file_attributes.txt";
    FILE* savFile = fopen(savPath, "w");
    if (savFile == NULL) {
        log_error("%s, %d: cannot save file attributes to \"%s\"\n", __func__, __LINE__, savPath);
        return;
    }

    FileAttr* cursor = ext->attrList->head->next;
    while (cursor != NULL) {
        const char* lastWriteTime = format_windows_filetime(&(cursor->lastWriteTime));
        fprintf(savFile, "%s, %10d bytes, %s\n", lastWriteTime, cursor->size, cursor->name);
        cursor = cursor->next;
    }

    fclose(savFile);
    printf("[INFO] save file attributes to file \"%s\" success\n", savPath);
}

void build_complete_path(char* buf, const char* extractPath, const char* fileName) {    
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
    DWORD dwAttrib = GetFileAttributes(path);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES 
        && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool recursive_create_parent_dirs(char* path) {
    char* cursor = path;

    while (*cursor != '\0') {
        if (*cursor == '\\') {
            /* split a substr here, just make it ends with '\0'. */
            *cursor = '\0';

            if (!is_dir_exist(path)) {
                if (!CreateDirectory(path, NULL)) {
                    DWORD err = GetLastError();
                    log_win_error(err, "%s, %d: CreateDirectory failed on \"%s\"", __func__, __LINE__, path);
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

bool save_single_file_data(FileAttr* attr, WinFile* wf, HANDLE hFile, char* buf, int32_t bufLen) {
    int32_t fileSize = attr->size;
    int32_t needLen;
    int32_t readLen;
    DWORD temp;
    
    while (fileSize > 0) {
        needLen = (fileSize < bufLen ? fileSize : bufLen);
        
        if (!win_file_read(wf, buf, needLen * sizeof(char), &temp)) {
            log_error("%s, %d: win_file_read failed", __func__, __LINE__);
            return false;
        }
        
        readLen = (int32_t)temp;
        decode_bytes(buf, buf, readLen);
        
        if (!WriteFile(hFile, buf, readLen, NULL, NULL)) {
            DWORD err = GetLastError();
            log_win_error(err, "%s, %d: WriteFile failed on \"%s\"", __func__, __LINE__, attr->name);
            return false;
        }

        fileSize -= readLen;
    }
    
    if (!SetFileTime(hFile, NULL, NULL, &(attr->lastWriteTime))) {
        DWORD err = GetLastError();
        log_win_error(err, "%s, %d: SetFileTime failed on \"%s\"", __func__, __LINE__, attr->name);
        return false;
    }
    
    return true;
}

bool parse_single_file(FileAttr* attr, WinFile* wf, const char* extractDir, char* buf, int32_t bufLen) {
    char path[MAX_PATH];
    build_complete_path(path, extractDir, attr->name);
    
    if (!recursive_create_parent_dirs(path)) {
        log_error("%s, %d: recursive_create_parent_dirs failed on \"%s\"", __func__, __LINE__, path);
        return false;
    }
    
    HANDLE hFile = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        log_win_error(err, "%s, %d: CreateFile failed on \"%s\"\n", __func__, __LINE__, path);
        return false;
    }
    
    if (!save_single_file_data(attr, wf, hFile, buf, bufLen)) {
        log_error("%s, %d: save_single_file_data failed on \"%s\"", __func__, __LINE__, path);
        CloseHandle(hFile);
        return false;
    }
    
    CloseHandle(hFile);
    return true;
}

bool parse_body(Extractor* ext, const char* extractDir) {
    printf("========= parse body =========\n");
    
    int32_t buf_size = 65536;
    char* buf = (char*)malloc(buf_size * sizeof(char));
    if (buf == NULL) {
        log_error("%s, %d: malloc failed\n", __func__, __LINE__);
        return false;
    }
    
    FileAttr* cursor = ext->attrList->head->next;
    while (cursor != NULL) {
        if (!parse_single_file(cursor, ext->pakFile, extractDir, buf, buf_size)) {
            log_error("%s, %d: parse_single_file failed\n", __func__, __LINE__);
            free(buf);
            return false;
        }
        
        cursor = cursor->next;
    }
    
    free(buf);
    printf("[INFO] body data write to dir \"%s\" success\n", extractDir);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s yours.pak savDir\n", argv[0]);
        return 1;
    }
    
    if (is_dir_exist(argv[2])) {
        fprintf(stderr, "given dir: \"%s\" is already existed\n", argv[2]);
        return 1;
    }
    
    Extractor* ext = create_extractor(argv[1]);
    if (ext == NULL) {
        log_error("create_extractor failed");
        return 1;
    }
    
    if (!parse_header(ext)) {
        log_error("parse_header failed");
        destroy_extractor(ext);
        return 1;
    }
    
    if (!parse_body(ext, argv[2])) {
        log_error("parse_body failed");
        destroy_extractor(ext);
        return 1;
    }
    
    save_file_attr_list(ext);
    destroy_extractor(ext);
    return 0;
}
