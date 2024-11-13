#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct Allocator     Allocator;
typedef struct FileAttr      FileAttr;
typedef struct FileAttrList  FileAttrList;
typedef struct PakHeader     PakHeader;
typedef struct Resource      Resource;

#define MAX_BLOCK_SIZE  328
#define MAX_FILE_NUM    16384

#define BUFFER_SIZE  8192

#define BYTES_OF_MAGIC       4
#define BYTES_OF_VERSION     4
#define BYTES_OF_FILE_SIZE   4
#define BYTES_OF_FILE_TIME   sizeof(FILETIME)

struct Allocator {
    char* buf;
    size_t used;
    size_t maxLen;
};

struct FileAttr {
    char* fileName;
    UINT32 fileSize;
    FILETIME lastWriteTime;
    FileAttr* next;
};

struct FileAttrList {
    FileAttr* head;
    FileAttr* tail;
    size_t length;
};

struct PakHeader {
    UCHAR magic[BYTES_OF_MAGIC];
    UCHAR version[BYTES_OF_VERSION];
    FileAttrList flist;
};

struct Resource {
    Allocator allocator;
    FILE* pakFile;
    FILE* filenameListSav;
};

BOOL allocator_init(Allocator* allocator, size_t size) {
    allocator->buf = (char*)malloc(size);
    if (allocator->buf == NULL) {
        return FALSE;
    }

    allocator->used = 0;
    allocator->maxLen = size;
    return TRUE;
}

void allocator_free(Allocator* allocator) {
    free(allocator->buf);
    allocator->maxLen = allocator->used = 0;
}

void* alloc_memory(Allocator* allocator, size_t size) {
    if (allocator->used + size >= allocator->maxLen) {
        return NULL;
    }

    allocator->used += size;
    return (void*)(allocator->buf + allocator->used - size);
}

BOOL resource_init(Resource* res, size_t size, const char* pakFilePath, const char* filenameListSavPath) {
    if (!allocator_init(&(res->allocator), size)) {
        return FALSE;
    }

    res->pakFile = fopen(pakFilePath, "rb");
    if (res->pakFile == NULL) {
        fprintf(stderr, "[ERROR] `%s` is not a valid pak file\n", pakFilePath);
        allocator_free(&(res->allocator));
        return FALSE;
    }

    res->filenameListSav = fopen(filenameListSavPath, "w");
    if (res->filenameListSav == NULL) {
        fprintf(stderr, "[ERROR] `%s` is not a valid save path\n", filenameListSavPath);
        fclose(res->pakFile);
        allocator_free(&(res->allocator));
        return FALSE;
    }

    return TRUE;
}

void resource_free(Resource* res) {
    allocator_free(&(res->allocator));
    fclose(res->pakFile);
    fclose(res->filenameListSav);
}

void* alloc_or_die(Resource* res, size_t size) {
    void* memory = alloc_memory(&(res->allocator), size);
    if (memory == NULL) {
        resource_free(res);
        fprintf(stderr, "[ERROR] memory is not enough to parse so many files\n");
        exit(EXIT_FAILURE);
    }

    return memory;
}

void file_attr_list_init(FileAttrList* flist) {
    flist->head = flist->tail = NULL;
    flist->length = 0;
}

void file_attr_list_add(FileAttrList* flist, FileAttr* attr) {
    attr->next = NULL;
    flist->length += 1;

    if (flist->head == NULL) {
        flist->head = flist->tail = attr;
    }
    else {
        flist->tail->next = attr;
        flist->tail = attr;
    }
}

void pak_header_init(PakHeader* header) {
    file_attr_list_init(&(header->flist));
}

/***************** parse. ****************/
#define decode_one_byte(c) \
    (unsigned char)(c ^ 0xf7)

#define decode_bytes(fromBuf, toBuf, len) do { \
    UINT32 i = 0; \
 \
    for (i = 0; i < (len); ++i) { \
        (toBuf)[i] = decode_one_byte((fromBuf)[i]); \
    } \
} while(0)

/* must be 0xc0, 0x4a, 0xc0, 0xba. */
void parse_magic(Resource* res, PakHeader* header) {
    fread(header->magic, sizeof(UCHAR), BYTES_OF_MAGIC, res->pakFile);
    decode_bytes(header->magic, header->magic, BYTES_OF_MAGIC);
}

/* must be 0x00, 0x00, 0x00, 0x00. */
void parse_version(Resource* res, PakHeader* header) {
    fread(header->version, sizeof(UCHAR), BYTES_OF_VERSION, res->pakFile);
    decode_bytes(header->version, header->version, BYTES_OF_VERSION);
}

BOOL reach_pak_header_end(Resource* res) {
    UCHAR flag;
    fread(&flag, sizeof(UCHAR), 1, res->pakFile);
    return decode_one_byte(flag) == 0x80;
}

void parse_file_name(Resource* res, FileAttr* attr) {
    UCHAR byte;
    UINT32 filenameLen;

    /* get the length of the file name. */
    fread(&byte, sizeof(UCHAR), 1, res->pakFile);
    filenameLen = (UINT32)decode_one_byte(byte);

    /* get the file name. */
    attr->fileName = alloc_or_die(res, (filenameLen + 1) * sizeof(char));
    attr->fileName[filenameLen] = '\0';
    fread(attr->fileName, sizeof(char), filenameLen, res->pakFile);
    decode_bytes(attr->fileName, attr->fileName, filenameLen);
}

void parse_file_size(Resource* res, FileAttr* attr) {
    UCHAR* buf = (UCHAR*)(&(attr->fileSize));
    
    fread(buf, sizeof(UCHAR), BYTES_OF_FILE_SIZE, res->pakFile);
    decode_bytes(buf, buf, BYTES_OF_FILE_SIZE);
}

void parse_file_last_write_time(Resource* res, FileAttr* attr) {
    UCHAR* buf = (UCHAR*)(&(attr->lastWriteTime));

    fread(buf, sizeof(UCHAR), BYTES_OF_FILE_TIME, res->pakFile);
    decode_bytes(buf, buf, BYTES_OF_FILE_TIME);
}

void parse_all_file_attrs(Resource* res, PakHeader* header) {
    FileAttr* attr;

    while (!feof(res->pakFile)) {
        if (reach_pak_header_end(res)) {
            break;
        }

        attr = alloc_or_die(res, sizeof(FileAttr));
        parse_file_name(res, attr);
        parse_file_size(res, attr);
        parse_file_last_write_time(res, attr);

        file_attr_list_add(&(header->flist), attr);
    }
}

void parse_pak_header(Resource* res, PakHeader* header) {
    parse_magic(res, header);
    parse_version(res, header);
    parse_all_file_attrs(res, header);
}

/***************** saving. ****************/
void build_complete_path(char* buf, size_t len, const char* extractPath, const char* fileName) {
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

BOOL is_dir_exist(const char* path) {
  DWORD dwAttrib = GetFileAttributes(path);

  return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
         (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL recursive_create_parent_dirs(char* path) {
    char* cursor = path;

    while (*cursor != '\0') {
        if (*cursor == '\\') {
            *cursor = '\0';

            if (!is_dir_exist(path)) {
                if (!CreateDirectory(path, NULL)) {
                    return FALSE;
                }
            }

            *cursor = '\\';
        }

        ++cursor;
    }

    return TRUE;
}

void parse_and_extract_one_file(Resource* res, FileAttr* attr, const char* extractPath, char* buf, size_t len) {
    char path[MAX_PATH];
    UINT32 fileSize = attr->fileSize;
    UINT32 readLen;
    HANDLE hFile;
    
    build_complete_path(path, MAX_PATH, extractPath, attr->fileName);
    
    if (!recursive_create_parent_dirs(path)) {
        fprintf(stderr, "[ERROR] can't create parent dirs for `%s`\n", path);
        return;
    }

    hFile = CreateFile(path, 
                    GENERIC_WRITE,
                    0,
                    NULL,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL);
        
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[ERROR] CreateFile() failed on `%s`\n", path);
        return;
    }

    while (fileSize > 0) {
        if (fileSize < len) {
            readLen = fread(buf, sizeof(char), fileSize, res->pakFile);
        }
        else {
            readLen = fread(buf, sizeof(char), len, res->pakFile);
        }

        decode_bytes(buf, buf, readLen);
        
        if (!WriteFile(hFile, buf, readLen, NULL, NULL)) {
            fprintf(stderr, "[ERROR] WriteFile() failed\n");
            goto tidy_up;
        }

        fileSize -= readLen;
    }

    if (!SetFileTime(hFile, NULL, NULL, &(attr->lastWriteTime))) {
        fprintf(stderr, "[ERROR] SetFileTime() failed\n");
        goto tidy_up;
    }

tidy_up:
    CloseHandle(hFile);
}

void save_file_name_list(Resource* res, PakHeader* header, const char* savPath) {
    FileAttr* attr = header->flist.head;

    while (attr != NULL) {
        fprintf(res->filenameListSav, "%s, %ld\n", attr->fileName, attr->fileSize);
        attr = attr->next;
    }

    printf("[SUCCESS] file name list is saved at `%s`.\n", savPath);
}

void extract_files(Resource* res, PakHeader* header, const char* extractPath) {
    FileAttr* attr = header->flist.head;
    char buf[BUFFER_SIZE];

    while (attr != NULL) {
        parse_and_extract_one_file(res, attr, extractPath, buf, BUFFER_SIZE);
        attr = attr->next;
    }

    printf("[SUCCESS] files are saved at `%s`.\n", extractPath);
}

int main(int argc, char* argv[]) {
    Resource res;
    PakHeader header;

    if (argc != 3) {
        fprintf(stderr, "usage: %s main.pak extract_dir\n", argv[0]);
        return 1;
    }

    if (!resource_init(&res, MAX_BLOCK_SIZE * MAX_FILE_NUM, argv[1], "filenames.txt")) {
        fprintf(stderr, "[ERROR] can't init resources\n");
        return 1;
    }

    pak_header_init(&header);
    parse_pak_header(&res, &header);

    printf("[SUCCESS] `%s` has %d files\n", argv[1], header.flist.length);
    save_file_name_list(&res, &header, "filenames.txt");
    printf("saving files ...\n");
    extract_files(&res, &header, argv[2]);

    resource_free(&res);
    return 0;
}
