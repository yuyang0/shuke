//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-12
//

#ifndef _ZMALLOC_H_
#define _ZMALLOC_H_ 1

#include <stdlib.h>
#include <string.h>

#define zmalloc malloc
#define zfree free
#define zrealloc realloc
#define zstrdup strdup

static inline void *zcalloc(size_t size) {
    return calloc(1, size);
}

static inline void *zmemdup(void *ptr, size_t size) {
    void *p = zmalloc(size);
    memcpy(p, ptr, size);
    return p;
}

#endif /* _ZMALLOC_H_ */
