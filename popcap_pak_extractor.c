/*
	@author yuanshixi
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

#define BYTES_OF_MAGIC       4
#define BYTES_OF_VERSION     4
#define BYTES_OF_FILE_SIZE   4
#define BYTES_OF_FILE_TIME   sizeof(FILETIME)

#define ERR_SUCCESS                                   0
#define ERR_FAILED                                    1
#define ERR_OUT_OF_MEMORY                             2
#define ERR_FILE_CANNOT_READ                          3
#define ERR_PARSE_HEADER_MAGIC                        4
#define ERR_PARSE_HEADER_VERSION                      5
#define ERR_PARSE_HEADER_INNER_FILE_NAME              6
#define ERR_PARSE_HEADER_INNER_FILE_SIZE              7
#define ERR_PARSE_HEADER_INNER_FILE_LAST_WRITE_TIME   8
#define ERR_CHECK_HEADER_MAGIC                        9
#define ERR_CHECK_HEADER_VERSION                      10
#define ERR_CREATE_PARENT_DIRS                        11
#define ERR_OS_WINDOWS_API                            12

typedef int Err;

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

const char* err_msg(Err err) {
	switch(err) {
		case ERR_SUCCESS:
			return "success";
		case ERR_OUT_OF_MEMORY:
			return "out of memory";
		case ERR_FILE_CANNOT_READ:
			return "can't read file";
		case ERR_PARSE_HEADER_MAGIC:
			return "can't parse .pak magic";
		case ERR_PARSE_HEADER_VERSION:
			return "can't parse .pak version";
		case ERR_PARSE_HEADER_INNER_FILE_NAME:
			return "can't parse .pak inner file name";
		case ERR_PARSE_HEADER_INNER_FILE_SIZE:
			return "can't parse .pak inner file size";
		case ERR_PARSE_HEADER_INNER_FILE_LAST_WRITE_TIME:
			return "can't parse .pak inner file last write time";
		case ERR_CHECK_HEADER_MAGIC:
			return "invalid .pak magic";
		case ERR_CHECK_HEADER_VERSION:
			return "invalid .pak version";
		case ERR_OS_WINDOWS_API:
			return format_windows_error_code(GetLastError());
		case ERR_CREATE_PARENT_DIRS:
			return "can't create parent directories with the given path";
		case ERR_FAILED:
		default:
			return "failed";
	}
}

Err file_attr_list_create(FileAttrList** list) {
	FileAttrList* temp = (FileAttrList*)malloc(sizeof(FileAttrList));
	if (temp == NULL) {
		*list = NULL;
		return ERR_OUT_OF_MEMORY;
	}

	temp->head = (FileAttr*)malloc(sizeof(FileAttr));
	if (temp->head == NULL) {
		free(temp);
		*list = NULL;
		return ERR_OUT_OF_MEMORY;
	}
	
	temp->head->next = NULL;
	temp->tail = temp->head;
	temp->length = 0;
	*list = temp;
	return ERR_SUCCESS;
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

Err pak_header_create(PakHeader** ph) {
	PakHeader* temp = (PakHeader*)malloc(sizeof(PakHeader));
	if (temp == NULL) {
		*ph = NULL;
		return ERR_OUT_OF_MEMORY;
	}
	
	Err err = file_attr_list_create(&(temp->attrList));
	if (err != ERR_SUCCESS) {
		free(temp);
		*ph = NULL;
		return err;
	}
	
	*ph = temp;
	return ERR_SUCCESS;
}

void pak_header_destroy(PakHeader* ph) {
	if (ph) {
		file_attr_list_destroy(ph->attrList);
		free(ph);
	}
}

#define decode_one_byte(ch) \
	(UCHAR)((ch) ^ 0xf7)

#define decode_bytes(fromBuf, toBuf, length) do { \
	for (int32_t i = 0; i < (length); ++i) { \
		toBuf[i] = decode_one_byte(fromBuf[i]); \
	} \
} while(0)

/*
	if can't read the require nmemb x size bytes data, then return ERR_FILE_CANNOT_READ,
	else return ERR_SUCCESS.
*/
Err read_binary_file(void *ptr, size_t size, size_t nmemb, FILE *stream, int32_t* readLen) {
	size_t len = fread(ptr, size, nmemb, stream);
	
	if (len != nmemb) {
		return ERR_FILE_CANNOT_READ;
	}
	else {
		if (readLen != NULL) {
			*readLen = len;	
		}
		
		return ERR_SUCCESS;
	}
}

Err parse_magic(FILE* pakFile, PakHeader* header) {
	Err err = read_binary_file(header->magic, sizeof(UCHAR), BYTES_OF_MAGIC, pakFile, NULL);
	if (err != ERR_SUCCESS) {
		return err;
	}
	
	decode_bytes(header->magic, header->magic, BYTES_OF_MAGIC);
	return ERR_SUCCESS;
}

Err parse_version(FILE* pakFile, PakHeader* header) {
	Err err = read_binary_file(header->version, sizeof(UCHAR), BYTES_OF_VERSION, pakFile, NULL);
	if (err != ERR_SUCCESS) {
		return err;
	}
	
	decode_bytes(header->version, header->version, BYTES_OF_VERSION);
	return ERR_SUCCESS;
}

Err reach_pak_header_end(FILE* pakFile, bool* reached) {
	UCHAR flag;
	Err err = read_binary_file(&flag, sizeof(UCHAR), 1, pakFile, NULL);
	
	if (err != ERR_SUCCESS) {
		return err;
	}
	else {
		*reached = (decode_one_byte(flag) == 0x80);
		return ERR_SUCCESS;
	}
}

Err parse_file_name(FILE* pakFile, FileAttr* attr) {
	UCHAR byte;
	Err err;

	/* get the length of the file name. */
	err = read_binary_file(&byte, sizeof(UCHAR), 1, pakFile, NULL);
	if (err != ERR_SUCCESS) {
		return err;
	}
	
	int32_t filenameLen = (int32_t)decode_one_byte(byte);

	/* get the file name. */
	attr->fileName = (char*)malloc((filenameLen + 1) * sizeof(char));
	if (attr->fileName == NULL) {
		return ERR_OUT_OF_MEMORY;
	}

	err = read_binary_file(attr->fileName, sizeof(char), filenameLen, pakFile, NULL);
	if (err != ERR_SUCCESS) {
		free(attr->fileName);
		return err;
	}
	
	attr->fileName[filenameLen] = '\0';
	decode_bytes(attr->fileName, attr->fileName, filenameLen);
	return ERR_SUCCESS;
}

Err parse_file_size(FILE* pakFile, FileAttr* attr) {
	UCHAR* buf = (UCHAR*)(&(attr->fileSize));
	
	Err err = read_binary_file(buf, sizeof(UCHAR), BYTES_OF_FILE_SIZE, pakFile, NULL);
	if (err != ERR_SUCCESS) {
		return err;
	}
	
	decode_bytes(buf, buf, BYTES_OF_FILE_SIZE);
	return ERR_SUCCESS;
}

Err parse_file_last_write_time(FILE* pakFile, FileAttr* attr) {
	UCHAR* buf = (UCHAR*)(&(attr->lastWriteTime));

	Err err = read_binary_file(buf, sizeof(UCHAR), BYTES_OF_FILE_TIME, pakFile, NULL);
	if (err != ERR_SUCCESS) {
		return err;
	}
	
	decode_bytes(buf, buf, (int32_t)BYTES_OF_FILE_TIME);
	return ERR_SUCCESS;
}

Err parse_all_file_attrs(FILE* pakFile, PakHeader* header) {
	Err err;
	bool reachEnd;
	
	while (true) {
		err = reach_pak_header_end(pakFile, &reachEnd);
		if (err != ERR_SUCCESS) {
			return err;
		}
		else if (reachEnd) {
			break;
		}

		FileAttr* attr = (FileAttr*)malloc(sizeof(FileAttr));
		if (attr == NULL) {
			return ERR_OUT_OF_MEMORY;
		}

		err = parse_file_name(pakFile, attr);
		if (err != ERR_SUCCESS) {
			free(attr); 
			return ERR_PARSE_HEADER_INNER_FILE_NAME;
		}
		
		err = parse_file_size(pakFile, attr);
		if (err != ERR_SUCCESS) {
			free(attr); 
			return ERR_PARSE_HEADER_INNER_FILE_SIZE;
		}
		
		err = parse_file_last_write_time(pakFile, attr);
		if (err != ERR_SUCCESS) {
			free(attr);
			return ERR_PARSE_HEADER_INNER_FILE_LAST_WRITE_TIME;
		}

		attr->next = NULL;
		file_attr_list_add_back(header->attrList, attr);
	}
	
	return ERR_SUCCESS;
}

bool check_magic(const PakHeader* header) {
	return (header->magic[0] == 0xc0)
		&& (header->magic[1] == 0x4a)
		&& (header->magic[2] == 0xc0)
		&& (header->magic[3] == 0xba);
}

bool check_version(const PakHeader* header) {
	return (header->version[0] == 0x00)
		&& (header->version[1] == 0x00)
		&& (header->version[2] == 0x00)
		&& (header->version[3] == 0x00);
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

/* create all parent directories from the given path. */
Err recursive_create_parent_dirs(char* path) {
	char* cursor = path;

	while (*cursor != '\0') {
		if (*cursor == '\\') {
			/* split a substr here, just make it ends with '\0'. */
			*cursor = '\0';

			if (!is_dir_exist(path)) {
				if (!CreateDirectory(path, NULL)) {
					return ERR_OS_WINDOWS_API;
				}
			}

			/* setting back. */
			*cursor = '\\';
		}

		++cursor;
	}

	return ERR_SUCCESS;
}

Err parse_pak_header(FILE* pakFile, PakHeader* header) {
	Err err;
	
	err = parse_magic(pakFile, header);
	if (err != ERR_SUCCESS) {
		return ERR_PARSE_HEADER_MAGIC;
	}

	if (!check_magic(header)) {
		return ERR_CHECK_HEADER_MAGIC;
	}

	err = parse_version(pakFile, header);
	if (err != ERR_SUCCESS) {
		return ERR_PARSE_HEADER_VERSION;
	}
	
	if (!check_version(header)) {
		return ERR_CHECK_HEADER_VERSION;
	}
	
	err = parse_all_file_attrs(pakFile, header);
	if (err != ERR_SUCCESS) {
		return err;
	}
	
	return ERR_SUCCESS;
}

Err save_one_file_data(FILE* pakFile, const FileAttr* attr, HANDLE hFile, char* buf, int32_t bufLen) {
	int32_t fileSize = attr->fileSize;
	int32_t readLen;
	int32_t needLen;
	Err err;
	
	while (fileSize > 0 && !feof(pakFile)) {
		needLen = (fileSize < bufLen ? fileSize : bufLen);
		
		err = read_binary_file(buf, sizeof(char), needLen, pakFile, &readLen);
		if (err != ERR_SUCCESS) {
			return err;
		}

		decode_bytes(buf, buf, readLen);
		
		if (!WriteFile(hFile, buf, readLen, NULL, NULL)) {
			return ERR_OS_WINDOWS_API;
		}

		fileSize -= readLen;
	}

	if (!SetFileTime(hFile, NULL, NULL, &(attr->lastWriteTime))) {
		return ERR_OS_WINDOWS_API;
	}
	
	return ERR_SUCCESS;
}

Err extract_one_file(FILE* pakFile, const FileAttr* attr, const char* extractPath, char* buf, size_t len) {
	char path[MAX_PATH];
	Err err;
	
	build_complete_path(path, extractPath, attr->fileName);
	
	err = recursive_create_parent_dirs(path);
	if (err != ERR_SUCCESS) {
		return ERR_CREATE_PARENT_DIRS;
	}

	HANDLE hFile = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return ERR_OS_WINDOWS_API;
	}

	err = save_one_file_data(pakFile, attr, hFile, buf, len);
	if (err != ERR_SUCCESS) {
		return err;
	}
	
	CloseHandle(hFile);
	return ERR_SUCCESS;
}

void extract_files(FILE* pakFile, const PakHeader* header, const char* extractPath) {
	int32_t buf_size = 8192;
	char* buf = (char*)malloc(buf_size * sizeof(char));
	
	if (buf == NULL) {
		fprintf(stderr, "extract files failed, please make sure that your computer have enough memory before executing this program.\n");
		return;
	}

	Err err;
	const FileAttr* cursor = header->attrList->head->next;
	
	while (cursor != NULL) {
		err = extract_one_file(pakFile, cursor, extractPath, buf, buf_size);
		
		if (err != ERR_SUCCESS) {
			free(buf);
			fprintf(stderr, "extract files failed when meet inner file: %s, error msg: %s\n", cursor->fileName, err_msg(err));
			return;
		}
		
		cursor = cursor->next;
	}

	free(buf);
	printf("extract success, files are saved in dir: %s.\n", extractPath);
}

void save_file_name_list(const PakHeader* header, const char* savPath) {
	FILE* savFile = fopen(savPath, "w");
	if (savFile == NULL) {
		fprintf(stderr, "can't save file name list to %s\n", savPath);
		return;
	}

	const FileAttr* cursor = header->attrList->head->next;

	while (cursor != NULL) {
		fprintf(savFile, "%s, %d bytes\n", cursor->fileName, cursor->fileSize);
		cursor = cursor->next;
	}

	fclose(savFile);
	printf("file name list is saved at: %s.\n", savPath);
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		fprintf(stderr, "usage: %s yours.pak savDir\n", argv[0]);
		return 1;
	}

	if (is_dir_exist(argv[2])) {
		fprintf(stderr, "given dir: %s is already existed, stop.\n", argv[2]);
		return 1;
	}

	FILE* pakFile = fopen(argv[1], "rb");
	if (pakFile == NULL) {
		fprintf(stderr, "can't open %s, stop.\n", argv[1]);
		return 1;
	}
	
	PakHeader* ph;
	Err err = pak_header_create(&ph);
	if (err != ERR_SUCCESS) {
		fprintf(stderr, "parse failed, can not create a .pak header handle, err msg: %s.\n", err_msg(err));
		fclose(pakFile);
		return 1;
	}
	
	err = parse_pak_header(pakFile, ph);
	if (err != ERR_SUCCESS) {
		fprintf(stderr, "parse pak header failed, %s.\n", err_msg(err));
		pak_header_destroy(ph);
		fclose(pakFile);
		return 1;
	}

	printf("\n%s has %d files inside.\n", argv[1], ph->attrList->length);
	save_file_name_list(ph, "pak_file_names.txt");
	extract_files(pakFile, ph, argv[2]);

	pak_header_destroy(ph);
	fclose(pakFile);
	return 0;
}
