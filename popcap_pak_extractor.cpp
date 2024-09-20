/**
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
 * This project only works for windows platform. please try to compile it with at least C++17.
*/
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>

#include <iostream>
#include <cstdio>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <string>
#include <fstream>
#include <system_error>
#include <vector>
#include <array>
#include <cstdint>

namespace fs = std::filesystem;

using uchar = unsigned char;

struct FileAttr {
    std::string fileName;
    uint32_t fileSize;
    FILETIME lastWriteTime;   // microsoft windows.
};

struct PakHeader {
    std::array<uchar, 4> magic;
    std::array<uchar, 4> version;
    std::vector<FileAttr> fileAttrList;
};

class PakFileExtractor {
    std::ifstream pakFile;
    PakHeader header;

    template<typename CharType>
    uchar decode_one_pak_byte(CharType c) {
        return static_cast<uchar>(c ^ 0xf7);
    }

    template<typename T>
    void decode_bytes(T* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            data[i] = decode_one_pak_byte(data[i]);
        }
    }

    bool is_pak_header_end() {
        char c;
        pakFile.read(&c, 1);
        return decode_one_pak_byte(c) == 0x80;
    }

    // parse 4 btyes for magic, must be 0xc0, 0x4a, 0xc0, 0xba.
    void parse_magic() {
        pakFile.read((char*)(header.magic.data()), header.magic.size());
        decode_bytes(header.magic.data(), header.magic.size());
    }

    // parse 4 bytes for version, must be all 0.
    void parse_version() {
        pakFile.read((char*)(header.version.data()), header.version.size());
        decode_bytes(header.version.data(), header.version.size());
    }

    // parse 1 byte for file name's length, then parse the file name.
    void parse_file_name(FileAttr& f) {
        char c;
        pakFile.read(&c, 1);
        uint32_t filenameLength = (uint32_t)(decode_one_pak_byte(c));

        f.fileName.resize(filenameLength);
        pakFile.read(f.fileName.data(), filenameLength);
        decode_bytes(f.fileName.data(), filenameLength);
    }

    // parse 4 bytes for file size. 
    void parse_file_size(FileAttr& f) {
        pakFile.read((char*)(&(f.fileSize)), 4);
        decode_bytes((char*)(&(f.fileSize)), 4);
    }

    void parse_file_last_write_time(FileAttr& f) {
        pakFile.read((char*)(&(f.lastWriteTime)), sizeof(FILETIME));
        decode_bytes((char*)(&(f.lastWriteTime)), sizeof(FILETIME));
    }

    void parse_each_file_attr() {
        while (!pakFile.eof()) {
            if (is_pak_header_end()) {
                break;
            }
        
            FileAttr f;
            parse_file_name(f);
            parse_file_size(f);
            parse_file_last_write_time(f);
            
            header.fileAttrList.emplace_back(f);
        }
    }

    void save_filename_list() {
        constexpr const char* pak_filename_list_path = "./pak_filename_list.txt";
        std::ofstream out{ pak_filename_list_path };

        for (auto& attr : header.fileAttrList) {
            out << attr.fileName << ", " << attr.fileSize << "\n";
        }

        std::cout << "Miku> pak filename list has been saved at \"" << pak_filename_list_path << "\"\n";
    }

    template<size_t N>
    void parse_and_save_one_file(FileAttr const& attr, fs::path const& p, std::array<char, N>& buf) {
        fs::path parentPath = p.parent_path();
        if (!fs::exists(parentPath)) {
            fs::create_directories(parentPath);
        }

        uint32_t fileSize = attr.fileSize;
        uint32_t readLen;

        HANDLE outFile = CreateFile(p.string().c_str(), 
                                    GENERIC_WRITE,
                                    0,
                                    nullptr,
                                    CREATE_NEW,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);

        if (outFile == INVALID_HANDLE_VALUE) {
            std::error_code ec(GetLastError(), std::system_category());
            std::cerr << "Miku> CreateFile() failed, " << ec.message() << "\n";
            throw std::system_error{ ec };
        }                                    

        while (fileSize > 0) {
            if (fileSize < buf.size()) {
                pakFile.read(buf.data(), fileSize);
            }
            else {
                pakFile.read(buf.data(), buf.size());
            }

            readLen = pakFile.gcount();
            decode_bytes(buf.data(), readLen);
            WriteFile(outFile, buf.data(), readLen, nullptr, nullptr);
            fileSize -= readLen;
        }

        SetFileTime(outFile, nullptr, nullptr, &(attr.lastWriteTime));
        CloseHandle(outFile);    
    }

    void parse_and_save_files(std::string const& saveRootDir) {
        fs::path root_dir{ saveRootDir };
        std::array<char, 8192> buf;

        for (const FileAttr& attr : header.fileAttrList) {
            parse_and_save_one_file(attr, root_dir / attr.fileName, buf);
        }

        std::cout << "Miku> all extracted files are saved at \"" << saveRootDir << "\"\n";
        pakFile.close();
    }
public:
    PakFileExtractor(std::string const& pakFilePath) 
        : pakFile{ pakFilePath, std::ios::binary } 
    {}

    void operator()(std::string const& saveRootDir) {
        parse_magic();
        parse_version();
        parse_each_file_attr();

        save_filename_list();
        parse_and_save_files(saveRootDir);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Miku> usage is " << argv[0] << " main.pak save_dir\n";
        return 0;
    }

    PakFileExtractor extractor{ argv[1] };
    extractor(argv[2]);
    return 0;
}
