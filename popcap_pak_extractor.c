/*
    @author yuanluo2
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
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct FileAttr      FileAttr;
typedef struct FileAttrList  FileAttrList;
typedef struct PakHeader     PakHeader;

#define BYTES_OF_MAGIC       4
#define BYTES_OF_VERSION     4
#define BYTES_OF_FILE_SIZE   4
#define BYTES_OF_FILE_TIME   sizeof(FILETIME)

struct FileAttr {
    char* fileName;
    uint32_t fileSize;
    FILETIME lastWriteTime;
    FileAttr* next;
};

struct FileAttrList {
    FileAttr* head;
    FileAttr* tail;
    uint32_t length;
};

struct PakHeader {
    UCHAR magic[BYTES_OF_MAGIC];
    UCHAR version[BYTES_OF_VERSION];
    FileAttrList* attrList;
};

FileAttrList* file_attr_list_create(void) {
    FileAttrList* list = (FileAttrList*)malloc(sizeof(FileAttrList));

    list->head = (FileAttr*)malloc(sizeof(FileAttr));
    list->head->next = NULL;

    list->tail = list->head;
    list->length = 0;

    return list;
}

void file_attr_list_destroy(FileAttrList* list) {
    if (list) {
        FileAttr* cursor = list->head->next;
        FileAttr* temp;

        while (cursor != NULL) {
            temp = cursor;
            cursor = cursor->next;

            free(temp->fileName);
            free(temp);
        }

        free(list->head);
        free(list);
    }
}

void file_attr_list_add_back(FileAttrList* list, FileAttr* attr) {
    list->tail->next = attr;
    list->tail = list->tail->next;

    ++(list->length);
}

PakHeader* pak_header_create(void) {
    PakHeader* ph = (PakHeader*)malloc(sizeof(PakHeader));
    ph->attrList = file_attr_list_create();

    return ph;
}

void pak_header_destroy(PakHeader* ph) {
    if (ph) {
        file_attr_list_destroy(ph->attrList);
        free(ph);
    }
}

/***************** parsing. ****************/
#define parsing_decode_one_byte(ch) \
    (UCHAR)((ch) ^ 0xf7)


#define parsing_decode_bytes(fromBuf, toBuf, length) do { \
    for (uint32_t i = 0; i < (length); ++i) { \
        toBuf[i] = parsing_decode_one_byte(fromBuf[i]); \
    } \
} while(0)


/* must be 0xc0, 0x4a, 0xc0, 0xba. */
void parsing_parse_magic(FILE* pakFile, PakHeader* header) {
    fread(header->magic, sizeof(UCHAR), BYTES_OF_MAGIC, pakFile);
    parsing_decode_bytes(header->magic, header->magic, BYTES_OF_MAGIC);
}

/* must be 0x00, 0x00, 0x00, 0x00. */
void parsing_parse_version(FILE* pakFile, PakHeader* header) {
    fread(header->version, sizeof(UCHAR), BYTES_OF_VERSION, pakFile);
    parsing_decode_bytes(header->version, header->version, BYTES_OF_VERSION);
}

bool parsing_reach_pak_header_end(FILE* pakFile) {
    UCHAR flag;
    fread(&flag, sizeof(UCHAR), 1, pakFile);
    return parsing_decode_one_byte(flag) == 0x80;
}

void parsing_parse_file_name(FILE* pakFile, FileAttr* attr) {
    UCHAR byte;
    uint32_t filenameLen;

    /* get the length of the file name. */
    fread(&byte, sizeof(UCHAR), 1, pakFile);
    filenameLen = (uint32_t)parsing_decode_one_byte(byte);

    /* get the file name. */
    attr->fileName = (char*)malloc((filenameLen + 1) * sizeof(char));
    attr->fileName[filenameLen] = '\0';

    fread(attr->fileName, sizeof(char), filenameLen, pakFile);
    parsing_decode_bytes(attr->fileName, attr->fileName, filenameLen);
}

void parsing_parse_file_size(FILE* pakFile, FileAttr* attr) {
    UCHAR* buf = (UCHAR*)(&(attr->fileSize));
    
    fread(buf, sizeof(UCHAR), BYTES_OF_FILE_SIZE, pakFile);
    parsing_decode_bytes(buf, buf, BYTES_OF_FILE_SIZE);
}

void parsing_parse_file_last_write_time(FILE* pakFile, FileAttr* attr) {
    UCHAR* buf = (UCHAR*)(&(attr->lastWriteTime));

    fread(buf, sizeof(UCHAR), BYTES_OF_FILE_TIME, pakFile);
    parsing_decode_bytes(buf, buf, BYTES_OF_FILE_TIME);
}

void parsing_parse_all_file_attrs(FILE* pakFile, PakHeader* header) {
    while (!feof(pakFile)) {
        if (parsing_reach_pak_header_end(pakFile)) {
            break;
        }

        FileAttr* attr = (FileAttr*)malloc(sizeof(FileAttr));
        attr->next = NULL;

        parsing_parse_file_name(pakFile, attr);
        parsing_parse_file_size(pakFile, attr);
        parsing_parse_file_last_write_time(pakFile, attr);

        file_attr_list_add_back(header->attrList, attr);
    }
}

void parsing_parse_pak_header(FILE* pakFile, PakHeader* header) {
    parsing_parse_magic(pakFile, header);
    parsing_parse_version(pakFile, header);
    parsing_parse_all_file_attrs(pakFile, header);
}

/***************** saving. ****************/
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

  return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
         (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

/* create all parent directories from the given path. */
bool recursive_create_parent_dirs(char* path) {
    char* cursor = path;

    while (*cursor != '\0') {
        if (*cursor == '\\') {
            /* split a substr here, just make it ends with '\0'. */
            *cursor = '\0';

            if (!is_dir_exist(path)) {
                if (!CreateDirectory(path, NULL)) {
                    return FALSE;
                }
            }

            /* setting back. */
            *cursor = '\\';
        }

        ++cursor;
    }

    return true;
}

/*
	same usage as fprintf, but this function would print the error message 
	associated with the error code.
*/
void win_log_err(FILE* stream, DWORD errorCode, const char* fmt, ...) {
    LPSTR message;
    va_list args;

    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                                 NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&message, 0, NULL);

    va_start(args, fmt);
    vfprintf(stream, fmt, args);
    fprintf(stream, ", %s\n", message);
    va_end(args);

    LocalFree(message);
}

void extract_one_file(FILE* pakFile, FileAttr* attr, const char* extractPath, char* buf, size_t len) {
    char path[MAX_PATH];
    
    build_complete_path(path, extractPath, attr->fileName);
    
    if (!recursive_create_parent_dirs(path)) {
        fprintf(stderr, "can't create parent dirs for `%s`, stop.\n", path);
        return;
    }

    HANDLE hFile = CreateFile(path, 
                                GENERIC_WRITE,
                                0,
                                NULL,
                                CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);
        
    if (hFile == INVALID_HANDLE_VALUE) {
        win_log_err(stderr, GetLastError(), "CreateFile() failed on `%s`, stop.\n", path);
        return;
    }

    uint32_t fileSize = attr->fileSize;
    uint32_t readLen;
    
    while (fileSize > 0) {
        if (fileSize < len) {
            readLen = fread(buf, sizeof(char), fileSize, pakFile);
        }
        else {
            readLen = fread(buf, sizeof(char), len, pakFile);
        }

        parsing_decode_bytes(buf, buf, readLen);
        
        if (!WriteFile(hFile, buf, readLen, NULL, NULL)) {
            win_log_err(stderr, GetLastError(), "WriteFile() failed, stop.\n");
            goto tidy_up;
        }

        fileSize -= readLen;
    }

    if (!SetFileTime(hFile, NULL, NULL, &(attr->lastWriteTime))) {
        win_log_err(stderr, GetLastError(), "SetFileTime() failed, stop.\n");
        goto tidy_up;
    }

tidy_up:
    CloseHandle(hFile);
}

void extract_files(FILE* pakFile, const PakHeader* header, const char* extractPath) {
    FileAttr* cursor = header->attrList->head->next;
    size_t buf_size = 8192;
    char* buf = (char*)malloc(buf_size * sizeof(char));

    while (cursor != NULL) {
        extract_one_file(pakFile, cursor, extractPath, buf, buf_size);
        cursor = cursor->next;
    }

    free(buf);
    printf("extract success, files are saved at `%s`.\n", extractPath);
}

void save_file_name_list(const PakHeader* header, const char* savPath) {
    FILE* savFile = fopen(savPath, "w");
    if (savFile == NULL) {
        fprintf(stderr, "can't save file name list to %s\n", savPath);
        return;
    }

    FileAttr* cursor = header->attrList->head->next;

    while (cursor != NULL) {
        fprintf(savFile, "%s, %d bytes\n", cursor->fileName, cursor->fileSize);
        cursor = cursor->next;
    }

    fclose(savFile);
    printf("file name list is saved at `%s`.\n", savPath);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "usage:\n");
        fprintf(stderr, "if you have a .pak file called `main.pak`, and you want to extract it to\n");
        fprintf(stderr, " a dir called `extract_dir`, then usage is: %s main.pak extract_dir\n", argv[0]);
        return 1;
    }

    if (is_dir_exist(argv[2])) {
        fprintf(stderr, "given dir is already exists: %s, stop.\n", argv[2]);
        return 1;
    }

    FILE* pakFile = fopen(argv[1], "rb");
    if (pakFile == NULL) {
        fprintf(stderr, "can't open %s, stop.\n", argv[1]);
        return 1;
    }

    PakHeader* ph = pak_header_create();
    parsing_parse_pak_header(pakFile, ph);

    printf("\n%s has %d files.\n", argv[1], ph->attrList->length);
    save_file_name_list(ph, "pak_file_names.txt");
    extract_files(pakFile, ph, argv[2]);

    pak_header_destroy(ph);
    fclose(pakFile);
    return 0;
}
