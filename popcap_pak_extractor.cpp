/**
 * @author yuanukim
 * @brief PopCap's .pak file extractor, written in C++14, only works for windows platform.
 * 
 * a very big thanks to https://github.com/nathaniel-daniel/popcap-pak-rs for giving 
 * the popcap .pak file's format:
 * 
 * Header 
 *   4 bytes - Magic (Should be [0xc0, 0x4a, 0xc0, 0xba])
 *   4 bytes - Version (Should be all 0) 
 *   loop 
 *       1 byte  - Record Flag (exit loop if 0x80)
 *       1 byte  - File name length (N) 
 *       N bytes - Filename 
 *       4 bytes - Filesize (u32)
 *       4 bytes - Last write time (Microsoft FILETIME struct)
 *   end
 *
 * Body
 *   for each record
 *       record.filesize bytes - File data
 *   end
 * 
*/
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>

#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <memory>
#include <algorithm>
#include <stdexcept>
#include <exception>
#include <system_error>
#include <chrono>
#include <utility>
#include <vector>
#include <array>
#include <cstdint>

using namespace std::chrono;
using namespace std::string_literals;
using uchar = unsigned char;

struct FileAttr {
    std::unique_ptr<char[]> fileName;
    uint32_t fileSize;
    FILETIME lastWriteTime;
};

struct Header {
    std::array<uchar, 4> magic;
    std::array<uchar, 4> version;
    std::vector<FileAttr> fileAttrList;
};

template<typename CharType>
uchar decode_one_byte(CharType c) noexcept {
    // using 0xf7 to decode the data in .pak file.
    return static_cast<uchar>(c ^ 0xf7);
}

template<typename CharType>
void decode_bytes(CharType* data, size_t len) noexcept {
    for (size_t i = 0; i < len; ++i) {
        data[i] = decode_one_byte(data[i]);
    }
}

class HeaderParser {
    bool is_pak_header_end(std::ifstream& f) {
        char c;
        f.read(&c, 1);
        return decode_one_byte(c) == 0x80;
    }

    void parse_magic(Header& header, std::ifstream& f) {
        f.read((char*)(header.magic.data()), header.magic.size());
        decode_bytes(header.magic.data(), header.magic.size());
    }

    void parse_version(Header& header, std::ifstream& f) {
        f.read((char*)(header.version.data()), header.version.size());
        decode_bytes(header.version.data(), header.version.size());
    }

    std::unique_ptr<char[]> init_file_name(size_t size) {
        return std::unique_ptr<char[]>(new char[size]);
    }

    void parse_file_name(FileAttr& attr, std::ifstream& f) {
        char c;
        f.read(&c, 1);

        // get the length of the file name.
        uint32_t fileNameLen = (uint32_t)decode_one_byte(c);
        attr.fileName = init_file_name(fileNameLen + 1);
        attr.fileName[fileNameLen] = '\0';

        // get file name.
        f.read(attr.fileName.get(), fileNameLen);
        decode_bytes(attr.fileName.get(), fileNameLen);
    }

    void parse_file_size(FileAttr& attr, std::ifstream& f) {    
        constexpr uint32_t FILE_SIZE_BYTES = 4;

        f.read((char*)(&(attr.fileSize)), FILE_SIZE_BYTES);
        decode_bytes((char*)(&(attr.fileSize)), FILE_SIZE_BYTES);
    }

    void parse_file_last_write_time(FileAttr& attr, std::ifstream& f) {
        f.read((char*)(&(attr.lastWriteTime)), sizeof(FILETIME));
        decode_bytes((char*)(&(attr.lastWriteTime)), sizeof(FILETIME));
    }

    bool check_magic(const Header& header) {
        return header.magic[0] == 0xC0 
            && header.magic[1] == 0x4A 
            && header.magic[2] == 0xC0 
            && header.magic[3] == 0xBA;
    }

    bool check_version(const Header& header) {
        return header.version[0] == 0x00 
            && header.version[1] == 0x00 
            && header.version[2] == 0x00 
            && header.version[3] == 0x00;
    }
public:
    HeaderParser() = default;

    void parse(Header& header, std::ifstream& f) {
        parse_magic(header, f);
        if (!check_magic(header)) {
            throw std::runtime_error{ "invalid .pak file, check Magic failed" };
        }

        parse_version(header, f);
        if (!check_version(header)) {
            throw std::runtime_error{ "invalid .pak file, check Version failed" };
        }

        while (!f.eof()) {
            if (is_pak_header_end(f)) {
                break;
            }

            FileAttr attr;
            parse_file_name(attr, f);
            parse_file_size(attr, f);
            parse_file_last_write_time(attr, f);

            header.fileAttrList.emplace_back(std::move(attr));
        }
    }
};

class WinFile {
    std::string path;
    HANDLE hFile;
public:
    WinFile(const char* _path) : path{ _path } {
        hFile = CreateFileA(_path, 
                            GENERIC_WRITE,
                            0,
                            nullptr,
                            CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL,
                            nullptr);

        if (hFile == INVALID_HANDLE_VALUE) {
            auto ec = GetLastError();
            throw std::system_error(ec, std::system_category(), "CreateFile() failed for: "s + path);
        }
    }

    ~WinFile() {
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
    }

    void write_data(const char* data, DWORD len) {
        if (!WriteFile(hFile, data, len, nullptr, nullptr)) {
            auto ec = GetLastError();
            throw std::system_error(ec, std::system_category(), "WriteFile() failed for: "s + path);
        }
    }

    void set_file_time(const FILETIME& ft) {
        if (!SetFileTime(hFile, nullptr, nullptr, &ft)) {
            auto ec = GetLastError();
            throw std::system_error(ec, std::system_category(), "SetFileTime() failed for: "s + path);
        }
    }
};

decltype(auto) write_win_filetime(const FILETIME& ft) {
    ULARGE_INTEGER uli;

    uli.HighPart = ft.dwHighDateTime;
    uli.LowPart = ft.dwLowDateTime;

    /* 
        windows file time begins from 1601/01/01, but unix timestamp 
        begins from 1970/01/01, so we have to minus this duration, 
        that's where 11644473600LL seconds come from.
        
        uli.QuadPart accurates to 10 ^ -7 seconds, so let it minus 116444736000000000LL first,
        then convert it to a system_clock would work.
    */
    system_clock::duration dur{ 100 * ((uint64_t)uli.QuadPart - 116444736000000000LL) };
    system_clock::time_point tp{ dur };

    time_t seconds = system_clock::to_time_t(tp);
    tm* localTime = std::localtime(&seconds);

    return std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
}

void save_file_attr_list(const Header& header, const char* savPath) {
    std::ofstream out{ savPath };

    for (const FileAttr& attr : header.fileAttrList) {
        out << write_win_filetime(attr.lastWriteTime) << ", " << std::setw(10) << attr.fileSize << " bytes, " << attr.fileName.get() << "\n";
    }
}

bool is_dir_exist(const char* path) noexcept {
    DWORD dwAttrib = GetFileAttributesA(path);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
            (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

/*
    concatenate 2 paths, null-terminated. only for windows platform.
*/
void path_concatenate(std::array<char, MAX_PATH>& buf, const char* parent, const char* sub) noexcept {
    bool hasBackslash = false;
    char* cursor = buf.data();

    while (*parent != '\0') {
        *cursor = *parent;

        ++cursor;
        ++parent;
    }

    --parent;
    if (*parent == '\\') {
        hasBackslash = true;
    }

    if (*sub != '\\' && !hasBackslash) {
        *cursor = '\\';
        ++cursor;
    }

    if (*sub == '\\' && hasBackslash) {
        ++sub;
    }

    while (*sub != '\0') {
        *cursor = *sub;

        ++cursor;
        ++sub;
    }

    *cursor = '\0';
}

/*
    constructs all parent directories of the given path if they're not exist.
*/
void construct_parent_dirs(char* path) {
    char* cursor = path;

    while (*cursor != '\0') {
        if (*cursor == '\\') {
            /* 
                CreateDirectory() needs a null terminated string, so we can play a trick here.
                this is why this function's arguments just need a char*, with this
                operation, we won't do any copy on the path.
            */
            *cursor = '\0';

            if (!is_dir_exist(path)) {
                if (!CreateDirectoryA(path, nullptr)) {
                    auto ec = GetLastError();
                    throw std::system_error(ec, std::system_category(), "CreateDirectory() failed for: "s + path);
                }
            }

            // reset back.
            *cursor = '\\';
        }

        ++cursor;
    }
}

template<size_t N>
void save_single_file_data(const FileAttr& attr, std::ifstream& f, std::array<char, N>& buf, const char* filePath) {
    uint32_t fileSize = attr.fileSize;
    uint32_t readLen = 0;
    WinFile wf{ filePath };

    while (fileSize > 0) {
        if (fileSize < buf.size()) {
            f.read(buf.data(), fileSize);
        }
        else {
            f.read(buf.data(), buf.size());
        }

        readLen = f.gcount();
        decode_bytes(buf.data(), readLen);

        wf.write_data(buf.data(), readLen);
        fileSize -= readLen;
    }

    wf.set_file_time(attr.lastWriteTime);
}

void save_file_data(const Header& header, std::ifstream& f, const char* rootPath) {
    std::array<char, 8192> buf;
    std::array<char, MAX_PATH> pathBuf;

    for (const FileAttr& attr : header.fileAttrList) {
        path_concatenate(pathBuf, rootPath, attr.fileName.get());
        construct_parent_dirs(pathBuf.data());
        save_single_file_data(attr, f, buf, pathBuf.data());
    }
}

void pak_extractor_entrance(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "If you have a .pak file called `main.pak`, and you want to \n";
        std::cerr << "extract it to a dir called `sav`, then usage is: ";
        std::cerr << argv[0] << " main.pak sav\n";
        return;
    }

    if (is_dir_exist(argv[2])) {
        std::cerr << "given dir is already exists: `" << argv[2] << "`\n";
        return;
    }

    Header header;
    HeaderParser parser;
    std::ifstream f;
    const char* fileAttrListSavPath = "./pak_file_attr_list.txt";
    
    f.open(argv[1], std::ios::binary);
    if (!f.is_open()) {
        std::cerr << "can't open file: `" << argv[1] << "`\n";
        return;
    }

    parser.parse(header, f);
    save_file_attr_list(header, fileAttrListSavPath);
    std::cout << "file attributes are saved at `" << fileAttrListSavPath << "`\n";
    std::cout << header.fileAttrList.size() << " files are found in `" << argv[1] << "`\n";

    save_file_data(header, f, argv[2]);
    std::cout << "files data are saved at directory `./" << argv[2] << "`\n";
}

int main(int argc, char* argv[]) {
    try {
        pak_extractor_entrance(argc, argv);
    }
    catch(const std::exception& e) {
        std::cerr << "unexpected error, " << e.what() << ", program quits.\n";
        return 1;
    }

    return 0;
}
