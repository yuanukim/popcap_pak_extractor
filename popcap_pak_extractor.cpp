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
 * This project only works for windows. try to compile it with at least C++17.
*/
#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <filesystem>
#include <string>
#include <fstream>
#include <vector>
#include <array>
#include <cstdint>
#include <Windows.h>

namespace fs = std::filesystem;

using uchar = unsigned char;

struct FileAttr {
    uchar flag;
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
    PakHeader pakHeader;
    std::array<char, 8192> buf;
    std::array<uchar, 8192> ubuf;

    uchar decode_one_pak_byte(char c) {
        return static_cast<uchar>(c ^ 0xf7);
    }

    bool is_pak_header_end(uchar flag) {
        return flag == 0x80;
    }

    // parse 4 btyes for magic, must be 0xc0, 0x4a, 0xc0, 0xba.
    void parse_magic() {
        pakFile.read(buf.data(), 4);
        for (size_t i = 0; i < 4; ++i) {
            pakHeader.magic[i] = decode_one_pak_byte(buf[i]);
        }
    }

    // parse 4 bytes for version, must be all 0.
    void parse_version() {
        pakFile.read(buf.data(), 4);
        for (size_t i = 0; i < 4; ++i) {
            pakHeader.version[i] = decode_one_pak_byte(buf[i]);
        }
    }

    // parse 1 byte for flag.
    void parse_file_flag(FileAttr& f) {
        pakFile.read(buf.data(), 1);
        f.flag = decode_one_pak_byte(buf[0]);
    }

    // parse 1 byte for file name's length, then parse the file name.
    void parse_file_name(FileAttr& f) {        
        pakFile.read(buf.data(), 1);
        uint8_t filenameLength = static_cast<uint8_t>(decode_one_pak_byte(buf[0]));

        pakFile.read(buf.data(), filenameLength);
        for (uint8_t i = 0; i < filenameLength; ++i) {
            f.fileName += static_cast<char>(decode_one_pak_byte(buf[i]));
        }
    }

    // parse 4 bytes for file size. 
    void parse_file_size(FileAttr& f) {
        pakFile.read(buf.data(), 4);

        for (int i = 0; i < 4; ++i) {
            ubuf[i] = decode_one_pak_byte(buf[i]);
        }

        f.fileSize = *(uint32_t*)(ubuf.data());
    }

    void parse_file_last_write_time(FileAttr& f) {
        constexpr size_t fileTimeStructSize = sizeof(FILETIME);

        pakFile.read(buf.data(), fileTimeStructSize);
        for (size_t i = 0; i < fileTimeStructSize; ++i) {
            ubuf[i] = decode_one_pak_byte(buf[i]);
        }

        f.lastWriteTime = *(FILETIME*)(ubuf.data());
    }

    void parse_each_file_attr() {
        while (true) {
            FileAttr f;

            parse_file_flag(f);
            if (is_pak_header_end(f.flag)) {
                break;
            }
        
            parse_file_name(f);
            parse_file_size(f);
            parse_file_last_write_time(f);
            
            pakHeader.fileAttrList.emplace_back(f);
        }
    }

    void parse_and_save_one_file(FileAttr const& attr, fs::path const& p) {
        fs::path parentPath = p.parent_path();
        if (!fs::exists(parentPath)) {
            fs::create_directories(parentPath);
        }

        std::ofstream out{ p, std::ios::binary };
        uint32_t fileSize = attr.fileSize;
        uint32_t readLen;

        while (fileSize > 0) {
            if (fileSize < buf.size()) {
                pakFile.read(buf.data(), fileSize);
            }
            else {
                pakFile.read(buf.data(), buf.size());
            }

            readLen = pakFile.gcount();
            for (uint32_t i = 0; i < readLen; ++i) {
                ubuf[i] = decode_one_pak_byte(buf[i]);
            }

            out.write(reinterpret_cast<const char*>(ubuf.data()), readLen);
            fileSize -= readLen;
        }
    }

    void parse_and_save_files() {
        fs::path root_dir{ "./popcap_pak_extract_result" };

        for (const FileAttr& attr : pakHeader.fileAttrList) {
            parse_and_save_one_file(attr, root_dir / attr.fileName);
        }

        pakFile.close();
    }
public:
    PakFileExtractor(std::string const& pakFilePath) 
        : pakFile{ pakFilePath, std::ios::binary } 
    {}

    const PakHeader& getPakHeader() const {
        return pakHeader;
    }

    void operator()() {
        parse_magic();
        parse_version();
        parse_each_file_attr();
        parse_and_save_files();
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <.pak file path>\n";
        return 0;
    }

    PakFileExtractor extractor{ argv[1] };
    extractor();
    return 0;
}
