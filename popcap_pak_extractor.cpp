/**
 * a very big thanks to https://github.com/nathaniel-daniel/popcap-pak-rs for giving 
 * the popcap .pak file's format:
 * 
 * Header 
 *   4 bytes - Magic (Should be [0xc0, 0x4a, 0xc0, 0xba])
 *   4 bytes - Version (Should be all 0) 
 *   loop 
 *       1 byte - Record Flag (exit loop if 0x80)
 *       1 byte - File name length (N) 
 *       N bytes - Filename 
 *       4 bytes - Filesize (u32)
 *       4 bytes - Last write time (Microsoft FILETIME struct)
 *   end
 *
 *   Body
 *   for each record
 *       record.filesize bytes - File data
 *   end
 * 
 * This project only works for windows. try to compile it with at least C++17.
*/
#include <iostream>
#include <algorithm>
#include <filesystem>
#include <string>
#include <fstream>
#include <vector>
#include <array>
#include <memory>
#include <cstdint>
#include <cstdlib>
#include <Windows.h>

namespace fs = std::filesystem;

inline constexpr uint32_t BUF_MAX_LEN = 8192;
inline constexpr uint32_t WINDOWS_OS_FILETIME_SIZE = sizeof(FILETIME);

struct Record {
    unsigned char flag;
    std::string fileName;
    uint32_t fileSize;
    FILETIME lastWriteTime;   // microsoft.
    std::string fileData;
};

struct PopcapPak {
    std::array<unsigned char, 4> magic;
    std::array<unsigned char, 4> version;
    std::vector<Record> records;
};

using PakPtr = std::shared_ptr<PopcapPak>;
using charBuf = std::array<char, BUF_MAX_LEN>;
using ucharBuf = std::array<unsigned char, BUF_MAX_LEN>;

static charBuf buf;
static ucharBuf ubuf;

inline unsigned char decode_one_pak_byte(char c) {
    return static_cast<unsigned char>(c ^ 0xf7);
}

inline bool is_pak_header_end(unsigned char flag) {
    return flag == 0x80;
}

void convert_char_buf_to_unsigned(uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
        ubuf[i] = decode_one_pak_byte(buf[i]);
    }
}

void extract_magic_version(PakPtr ptr, std::ifstream& in) {
    // parse magic, must be 0xc0, 0x4a, 0xc0, 0xba.
    in.read(buf.data(), 4);
    convert_char_buf_to_unsigned(4);
    std::copy(ubuf.begin(), ubuf.begin() + 4, ptr->magic.begin());

    // parse version, must be all 0.
    in.read(buf.data(), 4);
    convert_char_buf_to_unsigned(4);
    std::copy(ubuf.begin(), ubuf.begin() + 4, ptr->version.begin());
}

void extract_files_attributes(PakPtr ptr, std::ifstream& in) {
    while(true) {
        Record r;

        // check if this byte means the header is end.
        in.read(buf.data(), 1);
        r.flag = decode_one_pak_byte(buf[0]);
        if (is_pak_header_end(r.flag)) {
            break;
        }

        // get file name length.
        in.read(buf.data(), 1);
        unsigned char fileNameLengthByte = decode_one_pak_byte(buf[0]);
        uint8_t fileNameLength = static_cast<uint8_t>(fileNameLengthByte);

        // get file name.
        in.read(buf.data(), fileNameLength);
        convert_char_buf_to_unsigned(fileNameLength);
        r.fileName = std::string{ reinterpret_cast<const char*>(ubuf.data()), fileNameLength };

        // get file size. (uint32_t)
        in.read(buf.data(), 4);
        convert_char_buf_to_unsigned(4);
        r.fileSize = *reinterpret_cast<uint32_t*>(ubuf.data());

        // get last write time.
        in.read(buf.data(), WINDOWS_OS_FILETIME_SIZE);
        convert_char_buf_to_unsigned(WINDOWS_OS_FILETIME_SIZE);
        r.lastWriteTime = *reinterpret_cast<FILETIME*>(ubuf.data());

        ptr->records.emplace_back(r);
    }
}

void extract_every_file_data(PakPtr ptr, std::ifstream& in) {
    for (auto& r : ptr->records) {
        uint32_t fSize = r.fileSize;
        uint32_t readLen;

        while (fSize > 0) {
            if (fSize < BUF_MAX_LEN) {
                in.read(buf.data(), fSize);
            }
            else {
                in.read(buf.data(), BUF_MAX_LEN);
            }

            readLen = in.gcount();
            convert_char_buf_to_unsigned(readLen);

            r.fileData += std::string{ reinterpret_cast<const char*>(ubuf.data()), readLen };
            fSize -= readLen;
        }
    }
}

PakPtr extract_pak_file(std::string const& filePath) {
    auto ptr = std::make_shared<PopcapPak>();
    std::ifstream in{ filePath, std::ios::binary };

    extract_magic_version(ptr, in);
    extract_files_attributes(ptr, in);
    extract_every_file_data(ptr, in);

    return ptr;
}

void write_file_list(PakPtr ptr, std::string const& file) {
    std::ofstream out{ file };

    for (const auto& r : ptr->records) {
        out << r.fileName << "\n";
    }
}

void create_files(PakPtr ptr) {
    fs::path p{ "./extract_result" };

    for (const auto& r : ptr->records) {
        fs::path temp = p / r.fileName;
        auto dir = temp.parent_path();

        if (!fs::exists(dir)) {
            fs::create_directories(dir);
        }

        std::ofstream out{ temp, std::ios::binary };
        out << r.fileData;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <.pak file path>\n";
        return EXIT_FAILURE;
    }

    auto ptr = extract_pak_file(argv[1]);
    write_file_list(ptr, "./file_list.txt");
    create_files(ptr);
    return EXIT_SUCCESS;
}
