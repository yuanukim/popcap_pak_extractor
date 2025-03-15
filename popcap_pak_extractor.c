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

#define BYTES_OF_MAGIC       4
#define BYTES_OF_VERSION     4
#define BYTES_OF_FILE_SIZE   4
#define BYTES_OF_FILE_TIME   sizeof(FILETIME)

#define WINDOWS_ERROR_MSG_BUF_SIZE   256

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

FileAttrList* file_attr_list_create(void) {
	FileAttrList* list = (FileAttrList*)malloc(sizeof(FileAttrList));
	if (list == NULL) {
		return NULL;
	}

	list->head = (FileAttr*)malloc(sizeof(FileAttr));
	if (list->head == NULL) {
		free(list);
		return NULL;
	}
	
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
	
	if (ph != NULL) {
		ph->attrList = file_attr_list_create();
	}
	
	return ph;
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


int32_t read_file(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t readLen = fread(ptr, size, nmemb, stream);
	
	if (readLen < nmemb && ferror(stream)) {
		return -1;
	}
	else {
		return readLen;
	}
}

int parse_magic(FILE* pakFile, PakHeader* header) {
	if (read_file(header->magic, sizeof(UCHAR), BYTES_OF_MAGIC, pakFile) < 0) {
		return 0;
	}
	
	decode_bytes(header->magic, header->magic, BYTES_OF_MAGIC);
	return 1;
}

int parse_version(FILE* pakFile, PakHeader* header) {
	if (read_file(header->version, sizeof(UCHAR), BYTES_OF_VERSION, pakFile) < 0) {
		return 0;
	}
	
	decode_bytes(header->version, header->version, BYTES_OF_VERSION);
	return 1;
}

int reach_pak_header_end(FILE* pakFile) {
	UCHAR flag;
	
	if (read_file(&flag, sizeof(UCHAR), 1, pakFile) < 0) {
		return -1;
	}
	else {
		return decode_one_byte(flag) == 0x80;
	}
}

int parse_file_name(FILE* pakFile, FileAttr* attr) {
	UCHAR byte;
	int32_t filenameLen;

	/* get the length of the file name. */
	if (read_file(&byte, sizeof(UCHAR), 1, pakFile) < 0) {
		return 0;
	}
	
	filenameLen = (int32_t)decode_one_byte(byte);

	/* get the file name. */
	attr->fileName = (char*)malloc((filenameLen + 1) * sizeof(char));
	if (attr->fileName == NULL) {
		return 0;
	}

	if (read_file(attr->fileName, sizeof(char), filenameLen, pakFile) < 0) {
		free(attr->fileName);
		return 0;
	}
	
	attr->fileName[filenameLen] = '\0';
	decode_bytes(attr->fileName, attr->fileName, filenameLen);
	return 1;
}

int parse_file_size(FILE* pakFile, FileAttr* attr) {
	UCHAR* buf = (UCHAR*)(&(attr->fileSize));
	
	if (read_file(buf, sizeof(UCHAR), BYTES_OF_FILE_SIZE, pakFile) < 0) {
		return 0;
	}
	
	decode_bytes(buf, buf, BYTES_OF_FILE_SIZE);
	return 1;
}

int parse_file_last_write_time(FILE* pakFile, FileAttr* attr) {
	UCHAR* buf = (UCHAR*)(&(attr->lastWriteTime));

	if (read_file(buf, sizeof(UCHAR), BYTES_OF_FILE_TIME, pakFile) < 0) {
		return 0;
	}
	
	decode_bytes(buf, buf, BYTES_OF_FILE_TIME);
	return 1;
}

int parse_all_file_attrs(FILE* pakFile, PakHeader* header) {
	int ret;
	
	while (!feof(pakFile)) {
		ret = reach_pak_header_end(pakFile);
		if (ret < 0) {
			return 0;
		}
		else if (ret > 0) {
			break;
		}

		FileAttr* attr = (FileAttr*)malloc(sizeof(FileAttr));
		if (attr == NULL) {
			return 0;
		}
		
		attr->next = NULL;

		ret = parse_file_name(pakFile, attr) 
			&& parse_file_size(pakFile, attr) 
			&& parse_file_last_write_time(pakFile, attr);

		if (!ret) {
			free(attr);
			return 0;
		}

		file_attr_list_add_back(header->attrList, attr);
	}
	
	return 1;
}

int parse_pak_header(FILE* pakFile, PakHeader* header) {
	if (!parse_magic(pakFile, header)) {
		fprintf(stderr, "parse Magic with given .pak file failed.\n");
		return 0;
	}

	int magic_check_success = (header->magic[0] == 0xc0)
							&& (header->magic[1] == 0x4a)
							&& (header->magic[2] == 0xc0)
							&& (header->magic[3] == 0xba);
	
	if (!magic_check_success) {
		fprintf(stderr, "invalid .pak format, Magic check failed.\n");
		return 0;
	}

	if (!parse_version(pakFile, header)) {
		fprintf(stderr, "parse Version with given .pak file failed.\n");
		return 0;
	}
	
	int version_check_success = (header->version[0] == 0x00)
								&& (header->version[1] == 0x00)
								&& (header->version[2] == 0x00)
								&& (header->version[3] == 0x00);
	
	if (!version_check_success) {
		fprintf(stderr, "invalid .pak format, Version check failed.\n");
		return 0;
	}
	
	if (!parse_all_file_attrs(pakFile, header)) {
		fprintf(stderr, "parse all file attributes with given .pak file failed.\n");
		return 0;
	}
	
	return 1;
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

int is_dir_exist(const char* path) {
	DWORD dwAttrib = GetFileAttributes(path);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
		 (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

/* create all parent directories from the given path. */
int recursive_create_parent_dirs(char* path) {
	char* cursor = path;

	while (*cursor != '\0') {
		if (*cursor == '\\') {
			/* split a substr here, just make it ends with '\0'. */
			*cursor = '\0';

			if (!is_dir_exist(path)) {
				if (!CreateDirectory(path, NULL)) {
					return 0;
				}
			}

			/* setting back. */
			*cursor = '\\';
		}

		++cursor;
	}

	return 1;
}

/*
	using windows api to format error code into a human readable message.
	if this function format failed inside, then print this buf will just show empty.
*/
void format_windows_error_code(DWORD errCode, char* buf, size_t bufSize) {
	DWORD success = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
							 NULL, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)buf, bufSize, NULL);
							 
	if (success == 0) {
		buf[0] = '\0';
	}
}

int save_one_file_data(FILE* pakFile, FileAttr* attr, HANDLE hFile, char* buf, size_t len) {
	int32_t fileSize = attr->fileSize;
	int32_t readLen;
	char winErrMsg[WINDOWS_ERROR_MSG_BUF_SIZE];
	
	while (fileSize > 0 && !feof(pakFile)) {
		if (fileSize < len) {
			if ((readLen = read_file(buf, sizeof(char), fileSize, pakFile)) < 0) {
				fprintf(stderr, "read from .pak file meets error.\n");
				return 0;
			}
		}
		else {
			if ((readLen = read_file(buf, sizeof(char), len, pakFile)) < 0) {
				fprintf(stderr, "read from .pak file meets error.\n");
				return 0;
			}
		}

		decode_bytes(buf, buf, readLen);
		
		if (!WriteFile(hFile, buf, readLen, NULL, NULL)) {
			DWORD errCode = GetLastError();
			format_windows_error_code(errCode, winErrMsg, sizeof(winErrMsg) / sizeof(char));
			fprintf(stderr, "WriteFile() failed for %s, windows error code: %d, msg: %s.\n", attr->fileName, errCode, winErrMsg);
			return 0;
		}

		fileSize -= readLen;
	}

	if (!SetFileTime(hFile, NULL, NULL, &(attr->lastWriteTime))) {
		DWORD errCode = GetLastError();
		format_windows_error_code(errCode, winErrMsg, sizeof(winErrMsg) / sizeof(char));
		fprintf(stderr, "SetFileTime() failed for %s, windows error code: %d, msg: %s.\n", attr->fileName, errCode, winErrMsg);
		return 0;
	}
	
	return 1;
}

int extract_one_file(FILE* pakFile, FileAttr* attr, const char* extractPath, char* buf, size_t len) {
	char path[MAX_PATH];
	char winErrMsg[WINDOWS_ERROR_MSG_BUF_SIZE];
	
	build_complete_path(path, extractPath, attr->fileName);
	
	if (!recursive_create_parent_dirs(path)) {
		fprintf(stderr, "can't create parent dirs for `%s`, stop.\n", path);
		return 0;
	}

	HANDLE hFile = CreateFile(path, 
								GENERIC_WRITE,
								0,
								NULL,
								CREATE_NEW,
								FILE_ATTRIBUTE_NORMAL,
								NULL);
		
	if (hFile == INVALID_HANDLE_VALUE) {
		DWORD errCode = GetLastError();
		format_windows_error_code(errCode, winErrMsg, sizeof(winErrMsg) / sizeof(char));
		fprintf(stderr, "CreateFile() failed on `%s`, windows error code: %d, msg: %s.\n", path, errCode, winErrMsg);
		return 0;
	}

	int ret = save_one_file_data(pakFile, attr, hFile, buf, len);
	CloseHandle(hFile);
	return ret;
}

int extract_files(FILE* pakFile, const PakHeader* header, const char* extractPath) {
	FileAttr* cursor = header->attrList->head->next;
	size_t buf_size = 8192;
	char* buf = (char*)malloc(buf_size * sizeof(char));
	
	if (buf == NULL) {
		fprintf(stderr, "extract files failed, please make sure that your computer have enough memory before executing this program.\n");
		return 0;
	}

	while (cursor != NULL) {
		if (!extract_one_file(pakFile, cursor, extractPath, buf, buf_size)) {
			free(buf);
			fprintf(stderr, "extract inner file failed: %s\n", extractPath);
			return 0;
		}
		
		cursor = cursor->next;
	}

	free(buf);
	return 1;
}

int save_file_name_list(const PakHeader* header, const char* savPath) {
	FILE* savFile = fopen(savPath, "w");
	if (savFile == NULL) {
		fprintf(stderr, "can't save file name list to %s\n", savPath);
		return 0;
	}

	FileAttr* cursor = header->attrList->head->next;

	while (cursor != NULL) {
		fprintf(savFile, "%s, %d bytes\n", cursor->fileName, cursor->fileSize);
		cursor = cursor->next;
	}

	fclose(savFile);
	return 1;
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
		fprintf(stderr, "can't open %s, stop parse.\n", argv[1]);
		goto finally;
	}
	
	PakHeader* ph = pak_header_create();
	if (ph == NULL) {
		fprintf(stderr, "parse failed, please make sure that your computer have enough memory before executing this program.\n");
		goto finally;
	}
	
	if (!parse_pak_header(pakFile, ph)) {
		fprintf(stderr, "your file: %s, it's not a valid .pak file, can't parse.\n", argv[1]);
		goto finally;
	}

	printf("\n%s has %d files.\n", argv[1], ph->attrList->length);
	
	const char* savFileNameListPath = "pak_file_names.txt";
	
	if (!save_file_name_list(ph, savFileNameListPath)) {
		fprintf(stderr, "save file name list to %s failed.\n", savFileNameListPath);
		goto finally;
	}
	else {
		printf("file name list is saved at %s.\n", savFileNameListPath);
	}
	
	if (!extract_files(pakFile, ph, argv[2])) {
		fprintf(stderr, "your file: %s, extract its files failed.\n", argv[1]);
		goto finally;
	}
	else {
		printf("extract success, files are saved at %s.\n", argv[2]);
	}

finally:
	if (ph != NULL) {
		pak_header_destroy(ph);
	}
	
	if (pakFile != NULL) {
		fclose(pakFile);
	}

	return 0;
}
