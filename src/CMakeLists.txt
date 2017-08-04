
aux_source_directory(. DIR_SRCS)

include_directories(../3rd ../3rd/himongo/libbson/src/bson ../3rd/liburcu/include ../3rd/liburcu/src
        /home/yangyu/Documents/source-code/dpdk-stable-16.11.1/x86_64-native-linuxapp-gcc/include)

add_executable(shuke ${DIR_SRCS})
