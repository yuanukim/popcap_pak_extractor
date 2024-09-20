#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#define BYTES_OF_MAGIC       4
#define BYTES_OF_VERSION     4
#define BYTES_OF_FILE_SIZE   4
#define BYTES_OF_FILETIME    sizeof(FILETIME)

#define BUFFER_LEN   8192
#define FILE_NAME_LIST_SAV_PATH   "pak_file_name_list.txt"

struct FileAttribute {
    char* fileName;
    UINT32 fileSize;
    FILETIME lastWriteTime;
    struct FileAttribute* next;
};

struct Header {
    unsigned char magic[BYTES_OF_MAGIC];
    unsigned char version[BYTES_OF_VERSION];
    struct FileAttribute* attrListHead;
    struct FileAttribute* attrListTail;
};

FILE* pakFile;
FILE* filenameListSav;
char rwBuf[BUFFER_LEN];
char filesSaveRootDir[MAX_PATH];
struct Header header;

/*
    if some error occurs, log something and exit the program.
*/
void log_error_die(const char* fmt, ...) {
    va_list args;

    fprintf(stderr, "[%s %s] ", __DATE__, __TIME__);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    exit(EXIT_FAILURE);
}

void process_files_save_dir(const char* dir) {
    UINT32 len = 0;

    while (*dir != '\0') {
        filesSaveRootDir[len] = *dir;
        
        ++dir;
        ++len;
    }

    if (filesSaveRootDir[len - 1] == '/') {
        filesSaveRootDir[len - 1] = '\\';
    }
    else if (filesSaveRootDir[len - 1] != '\\') {
        filesSaveRootDir[len] = '\\';
        ++len;
    }

    filesSaveRootDir[len] = '\0';
}

void init_resources(const char* pakFilePath, const char* filesSaveDir) {
    header.attrListHead = NULL;
    header.attrListTail = NULL;

    process_files_save_dir(filesSaveDir);

    pakFile = fopen(pakFilePath, "rb");
    if (pakFile == NULL) {
        log_error_die("can't open .pak file: `%s`\n", pakFilePath);
    }

    filenameListSav = fopen(FILE_NAME_LIST_SAV_PATH, "w");
    if (filenameListSav == NULL) {
        fclose(pakFile);
        log_error_die("can't open `%s` to save filename list\n", FILE_NAME_LIST_SAV_PATH);
    }
}

void destroy_resources(void) {
    struct FileAttribute* cursor;

    fclose(pakFile);
    fclose(filenameListSav);

    while (header.attrListHead != NULL) {
        cursor = header.attrListHead->next;
        
        if (header.attrListHead->fileName != NULL) {
            free(header.attrListHead->fileName);
        }
        
        free(header.attrListHead);
        header.attrListHead = cursor;
    }
}

struct FileAttribute* header_add_new_attr(void) {
    struct FileAttribute* node = (struct FileAttribute*)malloc(sizeof(struct FileAttribute));
    if (node == NULL) {
        log_error_die("can't build a new FileAttribute struct, out of memory\n");
    }

    node->fileName = NULL;
    node->next = NULL;

    if (header.attrListHead == NULL) {
        header.attrListHead = node;
        header.attrListTail = node;
    }
    else {
        header.attrListTail->next = node;
        header.attrListTail = node;
    }

    return node;
}

#define decode_one_byte(c) \
    (unsigned char)(c ^ 0xf7)


#define decode_bytes(fromBuf, toBuf, len) do { \
    UINT32 i = 0; \
 \
    for (i = 0; i < (len); ++i) { \
        (toBuf)[i] = decode_one_byte((fromBuf)[i]); \
    } \
} while(0)


/* 
    magic number must be 0xc0, 0x4a, 0xc0, 0xba. 
*/
void parse_magic(void) {
    fread(header.magic, sizeof(unsigned char), BYTES_OF_MAGIC, pakFile);
    decode_bytes(header.magic, header.magic, BYTES_OF_MAGIC);
}

/* 
    version must be 0x00, 0x00, 0x00, 0x00. 
*/
void parse_version(void) {
    fread(header.version, sizeof(unsigned char), BYTES_OF_VERSION, pakFile);
    decode_bytes(header.version, header.version, BYTES_OF_VERSION);
}

BOOL is_pak_header_end(void) {
    unsigned char flag;
    fread(&flag, sizeof(unsigned char), 1, pakFile);
    return decode_one_byte(flag) == 0x80;
}

/*
    get the filename's length, then read those bytes as filename.
*/
void parse_file_name(struct FileAttribute* attr) {
    unsigned char filenameLenOneByte;
    UINT32 filenameLen;

    fread(&filenameLenOneByte, sizeof(unsigned char), 1, pakFile);
    filenameLen = (UINT32)decode_one_byte(filenameLenOneByte);

    attr->fileName = (char*)malloc((filenameLen + 1) * sizeof(char));
    if (attr->fileName == NULL) {
        log_error_die("can't allocate memory to fill filename\n");
    }

    fread(attr->fileName, sizeof(char), filenameLen, pakFile);
    decode_bytes(attr->fileName, attr->fileName, filenameLen);
    attr->fileName[filenameLen] = '\0';
}

void parse_file_size(struct FileAttribute* attr) {
    unsigned char* buf = (unsigned char*)(&(attr->fileSize));
    fread(buf, sizeof(unsigned char), BYTES_OF_FILE_SIZE, pakFile);
    decode_bytes(buf, buf, BYTES_OF_FILE_SIZE);
}

void parse_file_last_write_time(struct FileAttribute* attr) {
    unsigned char* buf = (unsigned char*)(&(attr->lastWriteTime));
    fread(buf, sizeof(unsigned char), BYTES_OF_FILETIME, pakFile);
    decode_bytes(buf, buf, BYTES_OF_FILETIME);
}

void parse_all_file_attrs(void) {
    struct FileAttribute* attr;

    while (!feof(pakFile)) {
        if (is_pak_header_end()) {
            break;
        }

        attr = header_add_new_attr();
        parse_file_name(attr);
        parse_file_size(attr);
        parse_file_last_write_time(attr);
    }
}

void parse_header(void) {
    parse_magic();
    parse_version();
    parse_all_file_attrs();
}

/*
    save all the file name and its file size.
*/
void save_file_name_list(void) {
    struct FileAttribute* cursor = header.attrListHead;

    while (cursor != NULL) {
        fprintf(filenameListSav, "%s, %ld\n", cursor->fileName, cursor->fileSize);
        cursor = cursor->next;
    }

    printf("file names are saved at `%s`\n", FILE_NAME_LIST_SAV_PATH);
}

char* construct_complete_path(struct FileAttribute* attr) {
    char* temp;
    char* pathCursor;
    char* completePath = (char*)malloc(MAX_PATH * sizeof(char));
    
    if (completePath == NULL) {
        log_error_die("can't allocate memory to save path\n");
    }

    pathCursor = completePath;
    temp = filesSaveRootDir;
    while (*temp != '\0') {
        *pathCursor = *temp;

        ++pathCursor;
        ++temp;
    }

    temp = attr->fileName;
    while (*temp != '\0') {
        *pathCursor = *temp;

        ++pathCursor;
        ++temp;
    }

    *pathCursor = '\0';
    return completePath;
}

BOOL is_dir_exist(const char* path) {
  DWORD dwAttrib = GetFileAttributes(path);

  return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
         (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

void recursive_create_parent_dirs(char* path) {
    char* cursor = path;

    while (*cursor != '\0') {
        if (*cursor == '\\') {
            *cursor = '\0';

            if (!is_dir_exist(path)) {
                if (!CreateDirectory(path, NULL)) {
                    log_error_die("even can't create directories on windows, %ld\n", GetLastError());
                }
            }

            *cursor = '\\';
        }

        ++cursor;
    }
}

void parse_and_save_one_file(struct FileAttribute* attr) {
    char* completePath;
    UINT32 fileSize = attr->fileSize;
    UINT32 readLen;
    HANDLE hFile;
    
    completePath = construct_complete_path(attr);
    recursive_create_parent_dirs(completePath);

    hFile = CreateFile(completePath, 
                    GENERIC_WRITE,
                    0,
                    NULL,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL);
        
    if (hFile == INVALID_HANDLE_VALUE) {
        log_error_die("call on CreateFile() failed on `%s`, %ld\n", completePath, GetLastError());
    }

    while (fileSize > 0) {
        if (fileSize < BUFFER_LEN) {
            readLen = fread(rwBuf, sizeof(char), fileSize, pakFile);
        }
        else {
            readLen = fread(rwBuf, sizeof(char), BUFFER_LEN, pakFile);
        }

        decode_bytes(rwBuf, rwBuf, readLen);
        WriteFile(hFile, rwBuf, readLen, NULL, NULL);
        fileSize -= readLen;
    }

    SetFileTime(hFile, NULL, NULL, &(attr->lastWriteTime));
    CloseHandle(hFile);
    free(completePath);
}

void save_body(void) {
    struct FileAttribute* attr = header.attrListHead;

    while (attr != NULL) {
        parse_and_save_one_file(attr);
        attr = attr->next;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        log_error_die("usage: %s main.pak extract_dir\n", argv[0]);
    }

    init_resources(argv[1], argv[2]);
    parse_header();
    save_file_name_list();
    save_body();
    destroy_resources();
    return 0;
}
