/**
 * @author yuanluo2
 * @brief PopCap's .pak file extractor, written in C++11.
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
 * This project only works for windows platform. please try to compile it with at least C++17.
*/
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>

#include <iostream>
#include <fstream>
#include <memory>
#include <algorithm>
#include <system_error>
#include <vector>
#include <array>
#include <cstdint>
#include <cstring>

using uchar = unsigned char;

/*
    C++ 's std::string .data() or .c_str() is const,
    in this program, I want to modify the underlying char* ptr,
    and I don't want const_cast<>(), so I write this string.

    the _data is always ends with '\0'.
*/
class CStr {
    char* _data;
    size_t _capacity;
    size_t _len;
public:
    CStr(const char* cstr, size_t cstrLen) {
        _len = cstrLen;
        _capacity = cstrLen + 1;
        _data = new char[_capacity];

        std::copy(cstr, cstr + cstrLen, _data);
        _data[_len] = '\0';
    }

    CStr(const char* cstr) : CStr{ cstr, strlen(cstr) } {}

    CStr(size_t capacity) : _capacity{ capacity }, _len{ 0 } {
        _data = new char[_capacity];
        _data[0] = '\0';
    }

    CStr() : CStr{ 32 } {}

    CStr(const CStr& other) {
        _capacity = other._capacity;
        _len = other._len;
        _data = new char[other._capacity];

        std::copy(other._data, other._data + other._capacity, _data);
    }

    CStr& operator=(const CStr& other) {
        if (this != &other) {
            _capacity = other._capacity;
            _len = other._len;

            delete _data;
            _data = new char[other._capacity];
            std::copy(other._data, other._data + other._capacity, _data);
        }

        return *this;
    }

    CStr(CStr&& other) noexcept {
        _capacity = other._capacity;
        _len = other._len;
        _data = other._data;

        other._data = nullptr;
    }

    CStr& operator=(CStr&& other) noexcept {
        if (this != &other) {
            _capacity = other._capacity;
            _len = other._len;
            _data = other._data;

            other._data = nullptr;
        }

        return *this;
    }

    ~CStr() noexcept {
        if (_data != nullptr) {
            delete _data;
        }
    }

    size_t length() const noexcept {
        return _len;
    }

    size_t capacity() const noexcept {
        return _capacity;
    }

    char* data() noexcept {
        return _data;
    }

    const char* data() const noexcept {
        return _data;
    }

    bool empty() const noexcept {
        return _len == 0;
    }

    char get_front() const noexcept {
        return _data[0];
    }

    char get_back() const noexcept {
        return _data[_len - 1];
    }

    void pop_back() noexcept {
        if (!empty()) {
            _len -= 1;
        }
    }

    void expand_capacity(size_t newCapacity) {
        if (newCapacity <= _capacity) {
            return;
        }

        char* temp = new char[newCapacity];
        std::copy(_data, _data + _capacity, temp);
        delete _data;

        _data = temp;
        _capacity = newCapacity;
    }

    void expand_length_with_terminated(size_t newLen) {
        expand_capacity(newLen + 1);
        _len = newLen;
        _data[_len] = '\0';
    }

    void append(const char* cstr, size_t cstrLen) {
        size_t needLen = _len + cstrLen + 1;

        if (needLen > _capacity) {
            expand_capacity(needLen);
        }

        std::copy(cstr, cstr + cstrLen, _data + _len);
        _len += cstrLen;
        _data[_len] = '\0';
    }

    void append(const char* cstr) {
        append(cstr, strlen(cstr));
    }

    void append(const CStr& str) {
        append(str.data(), str.length());
    }
};

struct FileAttr {
    CStr fileName;
    uint32_t fileSize;
    FILETIME lastWriteTime;
};

/*
    magic should be 0xC0, 0x4A, 0xC0, 0xBA,
    version should be all 0x00.
*/
struct Header {
    std::array<uchar, 4> magic;
    std::array<uchar, 4> version;
    std::vector<FileAttr> fileAttrList;
};

/*
    do some cleaning task at last.
    
    RAII maybe better, but this technique is fit here, so I use it.
*/
template<typename Func>
class Finally {
    Func f;
public:
    Finally(Func&& _f) : f{ _f } {}

    ~Finally() noexcept {
        f();
    }
};

template<typename Func>
Finally<Func> finally(Func&& f) {
    return Finally<Func>{ f };
}

template<typename CharType>
uchar decode_one_byte(CharType c) {
    // using 0xf7 to decode the data in .pak file.
    return static_cast<uchar>(c ^ 0xf7);
}

template<typename CharType>
void decode_bytes(CharType* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        data[i] = decode_one_byte(data[i]);
    }
}

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

void parse_file_name(FileAttr& attr, std::ifstream& f) {
    char c;
    f.read(&c, 1);

    // get the length of the file name.
    uint32_t fileNameLen = (uint32_t)decode_one_byte(c);
    attr.fileName.expand_length_with_terminated(fileNameLen);

    // get file name.
    f.read(attr.fileName.data(), fileNameLen);
    decode_bytes(attr.fileName.data(), fileNameLen);
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

void parse_each_file_attr(Header& header, std::ifstream& f) {
    while (!f.eof()) {
        if (is_pak_header_end(f)) {
            break;
        }

        FileAttr attr;
        parse_file_name(attr, f);
        parse_file_size(attr, f);
        parse_file_last_write_time(attr, f);

        header.fileAttrList.emplace_back(attr);
    }
}

void save_file_attr_list(const Header& header, const CStr& savPath) {
    std::ofstream out{ savPath.data() };

    for (const FileAttr& attr : header.fileAttrList) {
        out << attr.fileName.data() << ", " << attr.fileSize << "\n";
    }

    std::cout << "file attributes are saved at `" << savPath.data() << "`\n";
    std::cout << "this .pak file has " << header.fileAttrList.size() << " files\n";
}

bool is_dir_exist(const char* path) {
    DWORD dwAttrib = GetFileAttributes(path);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
            (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

/*
    concatenate 2 paths, only for windows platform.
*/
CStr path_concatenate(const CStr& parent, const CStr& sub) {
    CStr path;

    path.expand_capacity(parent.length() + 1 + sub.length() + 1);   // like: parent/su
    path.append(parent);

    if (path.get_back() == '\\') {
        path.pop_back();
    }

    if (sub.get_front() != '\\') {
        path.append("\\");
    }

    path.append(sub);
    return path;
}

/*
    constructs all parent directories of the given path if they're not exist.
*/
bool construct_parent_dirs(char* path, std::error_code& ec) {
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
                if (!CreateDirectory(path, nullptr)) {
                    ec.assign(GetLastError(), std::system_category());
                    return false;
                }
            }

            // reset back.
            *cursor = '\\';
        }

        ++cursor;
    }

    ec.clear();
    return true;
}

HANDLE create_new_write_file(CStr& path, std::error_code& ec) noexcept {
    HANDLE h = CreateFile(path.data(), 
                        GENERIC_WRITE,
                        0,
                        nullptr,
                        CREATE_NEW,
                        FILE_ATTRIBUTE_NORMAL,
                        nullptr);

    if (h == INVALID_HANDLE_VALUE) {
        ec.assign(GetLastError(), std::system_category());
    }
    else {
        ec.clear();
    }

    return h;
}

bool write_to_file(HANDLE hFile, const char* data, DWORD len, std::error_code& ec) noexcept {
    if (!WriteFile(hFile, data, len, nullptr, nullptr)) {
        ec.assign(GetLastError(), std::system_category());
        return false;
    }
    else {
        ec.clear();
        return true;
    }
}

bool set_file_time(HANDLE hFile, const FILETIME& ft, std::error_code& ec) noexcept {
    if (!SetFileTime(hFile, nullptr, nullptr, &ft)) {
        ec.assign(GetLastError(), std::system_category());
        return false;
    }
    else {
        ec.clear();
        return true;
    }
}

template<size_t N>
void save_single_file_data(const FileAttr& attr, std::ifstream& f, std::array<char, N>& buf, CStr& filePath) {
    uint32_t fileSize = attr.fileSize;
    uint32_t readLen = 0;
    std::error_code ec;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    
    hFile = create_new_write_file(filePath, ec);
    if (ec) {
        std::cerr << "create file failed: `" << filePath.data() << "`, " << ec.message() << "\n";
        return;
    }

    auto finally_close_file = [hFile](){ CloseHandle(hFile); };

    while (fileSize > 0) {
        if (fileSize < buf.size()) {
            f.read(buf.data(), fileSize);
        }
        else {
            f.read(buf.data(), buf.size());
        }

        readLen = f.gcount();
        decode_bytes(buf.data(), readLen);

        if (!write_to_file(hFile, buf.data(), readLen, ec)) {
            std::cerr << "write to file failed for file `" << filePath.data() << "`, " << ec.message() << "\n";
            return;
        }    
            
        fileSize -= readLen;
    }

    if (!set_file_time(hFile, attr.lastWriteTime, ec)) {
        std::cerr << "set last write time failed for file `" << filePath.data() << "`, " << ec.message() << "\n";
    }
}

void save_file_data(const Header& header, std::ifstream& f, const CStr& rootPath) {
    std::array<char, 8192> buf;
    std::error_code ec;   // C++11 's std::error_code is very fit for operating system api.

    for (const FileAttr& attr : header.fileAttrList) {
        CStr filePath = path_concatenate(rootPath, attr.fileName);
        
        if (!construct_parent_dirs(filePath.data(), ec)) {
            std::cerr << "create dir failed for `" << filePath.data() << "`, " << ec.message() << "\n";
            continue;
        }

        save_single_file_data(attr, f, buf, filePath);
    }

    std::cout << "files data are saved at `" << rootPath.data() << "`\n";
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "If you have a .pak file called `main.pak`, and you want to \n";
        std::cerr << "extract it to a dir called `sav`, then usage is: ";
        std::cerr << argv[0] << " main.pak sav\n";
        return 0;
    }

    if (is_dir_exist(argv[2])) {
        std::cerr << "given dir is exists: `" << argv[2] << "`\n";
        return 1;
    }

    Header header;
    std::ifstream f;
    
    f.open(argv[1], std::ios::binary);
    if (!f.is_open()) {
        std::cerr << "can't open file: `" << argv[1] << "`\n";
        return 1;
    }

    parse_magic(header, f);
    parse_version(header, f);
    parse_each_file_attr(header, f);

    save_file_attr_list(header, "./pak_file_attr_list.txt");
    save_file_data(header, f, argv[2]);
    return 0;
}
