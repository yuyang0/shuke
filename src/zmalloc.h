//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-12
//

#ifndef _ZMALLOC_H_
#define _ZMALLOC_H_ 1

#include <stdlib.h>
#include <string.h>

#include <rte_malloc.h>
#include <rte_memcpy.h>

#define SOCKET_ID_HEAP   (-1010)

static inline void *zalloc(size_t size) {
    return calloc(1, size);
}

static inline void *memdup(const void *ptr, size_t size) {
    void *p = malloc(size);
    memcpy(p, ptr, size);
    return p;
}

#if defined(USE_MALLOC) || defined (SK_TEST)

#define zmalloc(size) malloc(size)
#define zzalloc(size) zalloc(size);
#define zcalloc(size) calloc(1, size)
#define zrealloc(p, size) realloc(p, size)
#define zstrdup(s) strdup(s)
#define zmemdup memdup
#define zfree(p)   free(p)

#else

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

void malloc_set_oom_handler(void (*oom_handler)(size_t));
void socket_malloc_set_oom_handler(void (*oom_handler)(size_t));

void *socket_malloc(int socket_id, size_t size);
void *socket_zmalloc(int socket_id, size_t size);
void *socket_calloc(int socket_id, size_t nmemb, size_t size);
void *socket_realloc(int socket_id, void *ptr, size_t size);
void *socket_memdup(int socket_id, const void *ptr, size_t size);
void *socket_strdup(int socket_id, const char *s);
void socket_free(int socket_id, void *ptr);

#endif /* _ZMALLOC_H_ */
