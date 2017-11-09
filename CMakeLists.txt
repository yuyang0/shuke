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
        3rd/libyaml/include
        3rd/dpdk-stable-17.05.2/x86_64-native-linuxapp-gcc/include
)

add_executable(shuke ${SOURCE_FILES})
