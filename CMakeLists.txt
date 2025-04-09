cmake_minimum_required(VERSION 3.10)

project(PopcapPakExtractor)

option(USING_CPP "using C++ version, turn off this to compile C version." ON)

if (USING_CPP)
	message("-- using C++ version.")

	set(CMAKE_CXX_STANDARD 20)
	set(CMAKE_CXX_STANDARD_REQUIRED ON)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
	
	add_executable(${PROJECT_NAME} "popcap_pak_extractor.cpp")
else()
	message("-- using C version.")
	
	set(CMAKE_C_STANDARD 99)
	set(CMAKE_C_STANDARD_REQUIRED ON)
	set(CMAKE_C_EXTENSIONS OFF)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")

	add_executable(${PROJECT_NAME} "popcap_pak_extractor.c")
endif()
