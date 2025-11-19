/**
 * @author yuan
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

#include <windows.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <stdexcept>
#include <system_error>
#include <filesystem>
#include <string>
#include <memory>
#include <vector>
#include <array>
#include <utility>
#include <cstdint>
#include <ctime>

namespace fs = std::filesystem;

namespace parser {
    class ParserError : public std::runtime_error {
    public:
        ParserError(const std::string& msg) : std::runtime_error{ msg } {}
    };

    class FileNotFoundException : public ParserError {
    public:
        FileNotFoundException(const std::string& filePath) : ParserError{ filePath + " not found" } {}
    };

    class InvalidMagicException : public ParserError {
    public:
        InvalidMagicException() : ParserError{ "invalid magic field" } {}
    };

    class InvalidVersionException : public ParserError {
    public:
        InvalidVersionException() : ParserError{ "invalid version field" } {}
    };

    class FileBrokenException : public ParserError {
    public:
        FileBrokenException() : ParserError{ "file maybe broken" } {}
    };

    class WinFile {
        HANDLE handle;
        DWORD fileSize;
    public:
        WinFile() : handle{ INVALID_HANDLE_VALUE }, fileSize{ 0 } {}

        ~WinFile() {
            if (handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
            }
        }

        void open_file_to_read(const std::string& filePath) {
            handle = CreateFileA(filePath.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (handle == INVALID_HANDLE_VALUE) {
                throw FileNotFoundException{ filePath };
            }

            fileSize = GetFileSize(handle, nullptr);
            if (fileSize == INVALID_FILE_SIZE) {
                throw std::system_error(GetLastError(), std::system_category(), "GetFileSize failed");
            }
        }

        void open_file_to_write(const std::string& filePath) {
            handle = CreateFileA(filePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (handle == INVALID_HANDLE_VALUE) {
                throw std::system_error(GetLastError(), std::system_category(), "CreateFileA failed");
            }
        }

        DWORD read(char* buf, DWORD numOfBytesToRead) {
            if (fileSize < numOfBytesToRead) {
                throw FileBrokenException{};
            }

            DWORD numOfBytesRead;
            if (!ReadFile(handle, (LPVOID)buf, numOfBytesToRead, &numOfBytesRead, nullptr)) {
                throw std::system_error(GetLastError(), std::system_category(), "ReadFile failed");
            }

            fileSize -= numOfBytesRead;
            return numOfBytesRead;
        }

        void write(const char* buf, DWORD numOfBytesToWrite) {
            if (!WriteFile(handle, buf, numOfBytesToWrite, nullptr, nullptr)) {
                throw std::system_error(GetLastError(), std::system_category(), "WriteFile failed");
            }
        }

        void set_file_time(const FILETIME& ft) {
            if (!SetFileTime(handle, nullptr, nullptr, &ft)) {
                throw std::system_error(GetLastError(), std::system_category(), "SetFileTime failed");
            }
        }
    };

    struct FileAttr {
        std::unique_ptr<char[]> fileName;
        DWORD fileSize;
        FILETIME lastWriteTime;
    };

    class Parser {
        std::array<UCHAR, 4> magic;
        std::array<UCHAR, 4> version;
        std::vector<FileAttr> fileAttrs;
        WinFile wf;

        template<typename CharType>
        UCHAR decode_one_byte(CharType c) noexcept {
            // using 0xf7 to decode the data in .pak file.
            return static_cast<UCHAR>(c ^ 0xf7);
        }

        template<typename CharType>
        void decode_bytes(CharType* data, size_t len) noexcept {
            for (size_t i = 0; i < len; ++i) {
                data[i] = decode_one_byte(data[i]);
            }
        }

        bool reach_header_end() {
            char c;
            wf.read(&c, sizeof(c));
            return decode_one_byte(c) == 0x80;
        }

        bool check_magic() noexcept {
            return magic[0] == 0xC0 
                && magic[1] == 0x4A 
                && magic[2] == 0xC0 
                && magic[3] == 0xBA;
        }

        bool check_version() noexcept {
            return version[0] == 0x00 
                && version[1] == 0x00 
                && version[2] == 0x00 
                && version[3] == 0x00;
        }

        void parse_magic() {
            wf.read((char*)magic.data(), magic.size());
            decode_bytes(magic.data(), magic.size());

            if (!check_magic()) {
                throw InvalidMagicException{};
            }
        }

        void parse_version() {
            wf.read((char*)version.data(), version.size());
            decode_bytes(version.data(), version.size());

            if (!check_version()) {
                throw InvalidVersionException{};
            }
        }

        std::unique_ptr<char[]> init_file_name(size_t size) {
            return std::unique_ptr<char[]>(new char[size]);
        }

        void parse_file_name(FileAttr& attr) {
            char c;
            wf.read(&c, sizeof(char));

            // get the length of the file name.
            uint32_t fileNameLen = (uint32_t)decode_one_byte(c);
            attr.fileName = init_file_name(fileNameLen + 1);
            attr.fileName[fileNameLen] = '\0';

            // get file name.
            wf.read(attr.fileName.get(), fileNameLen);
            decode_bytes(attr.fileName.get(), fileNameLen);
        }

        void parse_file_size(FileAttr& attr) {
            constexpr uint32_t FILE_SIZE_BYTES = 4;
            wf.read((char*)(&(attr.fileSize)), FILE_SIZE_BYTES);
            decode_bytes((char*)(&(attr.fileSize)), FILE_SIZE_BYTES);
        }

        void parse_file_last_write_time(FileAttr& attr) {
            wf.read((char*)(&(attr.lastWriteTime)), sizeof(FILETIME));
            decode_bytes((char*)(&(attr.lastWriteTime)), sizeof(FILETIME));
        }

        template<size_t N>
        void save_single_file(const FileAttr& attr, std::array<char, N>& buf, const fs::path& p) {
            DWORD fileSize = attr.fileSize;
            DWORD readLen = 0;
            DWORD needLen = 0;
            
            WinFile tmpFile;
            tmpFile.open_file_to_write(p.string());

            while (fileSize > 0) {
                needLen = (fileSize < buf.size() ? fileSize : buf.size());
                readLen = wf.read(buf.data(), needLen);

                decode_bytes(buf.data(), buf.size());
                tmpFile.write(buf.data(), readLen);

                fileSize -= readLen;
            }

            tmpFile.set_file_time(attr.lastWriteTime);
        }
    public:
        Parser() {}

        const std::vector<FileAttr>& get_file_attrs() const noexcept {
            return fileAttrs;
        }

        void open(const std::string& filePath) {
            wf.open_file_to_read(filePath);
        }

        void parse_header() {
            parse_magic();
            parse_version();

            while (true) {
                if (reach_header_end()) {
                    return;
                }

                FileAttr attr;

                parse_file_name(attr);
                parse_file_size(attr);
                parse_file_last_write_time(attr);
                
                fileAttrs.emplace_back(std::move(attr));
            }
        }

        void save_body(const std::string& toDir) {
            std::array<char, 8192> buf;

            for (const FileAttr& attr : fileAttrs) {
                fs::path p{ toDir };
                p.append(attr.fileName.get());

                fs::path parentDir = p.parent_path();
                if (!fs::exists(parentDir)) {
                    fs::create_directories(parentDir);
                }

                save_single_file(attr, buf, p);
            }
        }
    };
};

// not thread safe.
const char* format_windows_filetime(const FILETIME& ft) {
    static char buf[32];
    ULARGE_INTEGER ull;
    
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;

    /* 
        windows file time begins from 1601/01/01, but unix timestamp 
        begins from 1970/01/01, so we have to minus this duration, 
        that's where 11644473600LL seconds come from.
        
        uli.QuadPart accurates to 10 ^ -7 seconds.
    */
    time_t timestamp = (time_t)((ull.QuadPart / 10000000ULL) - 11644473600ULL);
    struct tm* timeinfo = localtime(&timestamp);
    strftime(buf, sizeof(buf) / sizeof(char), "%Y-%m-%d %H:%M:%S", timeinfo);
    return buf;
}

void save_file_attrs(const std::vector<parser::FileAttr>& attrs, const std::string& savFile) {
    std::ofstream out{ savFile };

    for (const parser::FileAttr& attr : attrs) {
        out << format_windows_filetime(attr.lastWriteTime) << "  " << std::setw(10) << attr.fileSize << " bytes  " << attr.fileName.get() << "\n";
    }

    out.close();
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <.pak> <sav_dir>\n";
        return 1;
    }

    if (fs::is_directory(argv[2])) {
        std::cerr << "dir: " << argv[2] << " is not empty.\n";
        return 1;
    }

    try {
        parser::Parser pakParser;
        
        pakParser.open(argv[1]);
        pakParser.parse_header();
        pakParser.save_body(argv[2]);

        save_file_attrs(pakParser.get_file_attrs(), "file_attrs.txt");
        std::cout << "parse success, file attributes has been wriiten to `file_attrs.txt`\n";
    }
    catch(const parser::ParserError& pe) {
        std::cerr << "parser error, " << pe.what() << "\n";
    }
    catch(const std::system_error& se) {
        std::cerr << "system error, " << se.code() << ", " << se.what() << "\n";
    }
    catch(const std::exception& e) {
        std::cerr << "standard exception, " << e.what() << "\n";
    }

    return 0;
}
