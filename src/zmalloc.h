//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-12
//

#ifndef _ZMALLOC_H_
#define _ZMALLOC_H_ 1

#include <stdlib.h>
#include <string.h>

#if defined(USE_MALLOC) || defined (SK_TEST)

#define zmalloc(size) malloc(size)
#define zcalloc(size) calloc(1, size)
#define zrealloc(p, size) realloc(p, size)
#define zstrdup(s) strdup(s)
#define zfree(p)   free(p)

static inline void *zmemdup(const void *ptr, size_t size) {
    void *p = zmalloc(size);
    memcpy(p, ptr, size);
    return p;
}

#else

#include <rte_malloc.h>
#include <rte_memcpy.h>

static inline void *zmalloc(size_t size) {
    return rte_malloc(NULL, size, 0);
}

static inline void *zcalloc(size_t size) {
    return rte_calloc(NULL, 1, size, 0);
}

static inline void *zrealloc(void *ptr, size_t size) {
    return rte_realloc(ptr, size, 0);
}

static inline void *zmemdup(const void *ptr, size_t size) {
    void *p = zmalloc(size);
    rte_memcpy(p, ptr, size);
    return p;
}

static inline char *zstrdup(const char *s) {
    return zmemdup(s, strlen(s)+1);
}

static inline void zfree(void *ptr) {
    rte_free(ptr);
}

#endif

#define hmalloc malloc
#define hfree free
#define hrealloc realloc
#define hstrdup strdup

#endif /* _ZMALLOC_H_ */
