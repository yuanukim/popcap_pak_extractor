# popcap_pak_extractor
##### 这是一个专用于提取 popcap 的 .pak 内部文件的提取器，我已经测试了宝石迷阵3，宝石迷阵 Twist 和植物大战僵尸的pak文件。这个程序只能在windows系统上使用。
##### 这个项目同时提供 C 和 C++ 的版本，可以自行修改 CMakeLists.txt 来决定编译哪一个版本。另外，有一个单独的 cpp20 的版本，这是专门用 C++20 实现的，它主要用于实验一些新的 C++ 特性，不是百分百可靠的。
##### 非常感谢 https://github.com/nathaniel-daniel/popcap-pak-rs 这个项目，我通过它理解了 popcap 的 .pak 文件格式。
##### ===============================================================================================================================================================================================================
##### A tool to extract the files from the popcap's .pak file, I have tested it with Bejeweled 3, Bejeweled Twist and PVZ's .pak files. only works for windows platform.
##### This project provides both C and C++ version, you can modify the CMakeLists.txt to determine which one to be built. A single cpp20 version is also provided, it is used to test some new C++ features, it is not 100% reliable.
##### A very big thanks to https://github.com/nathaniel-daniel/popcap-pak-rs , I came to realize the popcap's .pak file format through this project.
```shell
cd popcap_pak_extractor

mkdir build
cd build

cmake -G "MinGW Makefiles" -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ ..
mingw32-make -j 4
```
