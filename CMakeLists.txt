cmake_minimum_required(VERSION 3.5)
project(shuke C)

file(GLOB_RECURSE SOURCE_FILES
        "src/*.c"
        "src/*.h"
        )

include_directories(
        3rd
        3rd/himongo/libbson/src/bson
        3rd/liburcu/include
        3rd/liburcu/src
        3rd/luajit/src
        3rd/dpdk/x86_64-native-linuxapp-gcc/include
)

add_executable(shuke ${SOURCE_FILES})
