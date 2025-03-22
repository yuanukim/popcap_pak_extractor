/**
 * @author yuanshixi
 * @brief PopCap's .pak file extractor, written in C++20, only works for windows platform.
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
#include <exception>
#include <stdexcept>
#include <fstream>
#include <string>
#include <memory>
#include <algorithm>
#include <filesystem>
#include <chrono>
#include <utility>
#include <vector>
#include <array>
#include <cstdint>

namespace fs = std::filesystem;

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

void save_file_attr_list(const Header& header, const char* savPath) {
    std::ofstream out{ savPath };

    for (const FileAttr& attr : header.fileAttrList) {
        out << attr.fileName.get() << ", " << attr.fileSize << " bytes\n";
    }
}

/*
    Before writing this function, I have tried the answer from:
    https://stackoverflow.com/questions/72030923/how-to-convert-a-windows-filetime-to-a-stdchronotime-pointstdchronofile

    be cautions that, this solution only works for vc++, but it would get a really different result on other compilers, 
    such as my winlibs-x86_64-posix-seh-gcc-14.1.0-mingw-w64msvcrt-11.0.1-r1 g++ compiler and my Msys2 mingw compiler.
    so I consider to create the system_clock first, then convert it to file_clock. 

    if using visual C++, the conversion could be easily replaced by using file_clock::duration and file_clock::time_point.
*/
file_clock::time_point convert_win_FILETIME_to_file_clock(const FILETIME& ft) {
    ULARGE_INTEGER uli;

    uli.HighPart = ft.dwHighDateTime;
    uli.LowPart = ft.dwLowDateTime;

    /* 
        windows file time begins from 1601/01/01, but unix timestamp 
        begins from 1970/01/01, so we have to minus this duration, 
        that's where 11644473600LL seconds  come from.
        
        uli.QuadPart accurates to 10 ^ -7 seconds, so let it minus 116444736000000000LL first,
        then convert it to a system_clock would work.
    */
    uint64_t nanosec = (static_cast<uint64_t>(uli.QuadPart) - 116444736000000000LL) * 100;
    
    system_clock::duration dur{ nanosec };
    system_clock::time_point tp{ dur };

    /*
        accroding to the microsoft's document: https://learn.microsoft.com/en-us/cpp/standard-library/file-clock-class?view=msvc-170
        whether std::chrono::file_clock provide from_utc, to_utc, from_sys, to_sys is actually defined by vendor, so it is safe to use 
        clock_cast here.
    */
    return clock_cast<file_clock>(tp);
}

template<size_t N>
void save_single_file_data(const FileAttr& attr, std::ifstream& f, std::array<char, N>& buf, const fs::path& p) {
    uint32_t fileSize = attr.fileSize;
    uint32_t readLen = 0;
    std::ofstream out{ p.string(), std::ios::binary };

    while (fileSize > 0) {
        if (fileSize < buf.size()) {
            f.read(buf.data(), fileSize);
        }
        else {
            f.read(buf.data(), buf.size());
        }

        readLen = f.gcount();
        decode_bytes(buf.data(), readLen);

        out.write(buf.data(), readLen);
        fileSize -= readLen;
    }

    /*
        be cautions here,
        you Must do this close() first before calling std::filesystem::last_write_time(),
        otherwise, you may find your file's last write time is the current time, this is
        really a silly mistake, and it's really easy to be made.

        The same question can be found at:
        https://stackoverflow.com/questions/38158037/why-cant-i-change-the-last-write-time-of-my-newly-created-files
    */
    out.close();
    auto fc = convert_win_FILETIME_to_file_clock(attr.lastWriteTime);
    fs::last_write_time(p, fc);
}

void save_file_data(const Header& header, std::ifstream& f, const std::string& rootPath) {
    std::array<char, 8192> buf;

    for (const FileAttr& attr : header.fileAttrList) {
        fs::path p{ rootPath };
        p.append(attr.fileName.get());

        fs::path parentDir = p.parent_path();
        if (!fs::exists(parentDir)) {
            fs::create_directories(parentDir);
        }

        save_single_file_data(attr, f, buf, p);
    }
}

void pak_extractor_entrance(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "If you have a .pak file called `main.pak`, and you want to \n";
        std::cerr << "extract it to a dir called `sav`, then usage is: ";
        std::cerr << argv[0] << " main.pak sav\n";
        return;
    }

    if (fs::is_directory(argv[2])) {
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
