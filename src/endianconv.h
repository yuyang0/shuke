#ifndef __ENDIANCONV_H
#define __ENDIANCONV_H

#include <stdint.h>

#include <rte_byteorder.h>

// dump integer to big endian encode string
static inline void dump16be(uint16_t v, char *buf) {
    uint16_t *tmp16 = (uint16_t *)buf;
    *tmp16 = rte_cpu_to_be_16(v);
}

static void dump32be(uint32_t v, char *buf) {
    uint32_t *tmp32 = (uint32_t *)buf;
    *tmp32 = rte_cpu_to_be_32(v);
}

static void dump64be(uint64_t v, char *buf) {
    uint64_t *tmp64 = (uint64_t *)buf;
    *tmp64 = rte_cpu_to_be_64(v);
}

// load integer from big endian encode string
static inline uint16_t load16be(char *buf) {
    return rte_be_to_cpu_16(*((uint16_t *)buf));
}

static inline uint32_t load32be(char *buf) {
    return rte_be_to_cpu_32(*((uint32_t *)buf));
}

static inline uint64_t load64be(char *buf) {
    return rte_be_to_cpu_64(*((uint64_t *)buf));
}

#endif