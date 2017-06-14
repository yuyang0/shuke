//
// Created by yangyu on 17-6-13.
//

#include <rte_malloc.h>
#include <rte_memcpy.h>

#include "zmalloc.h"

static void zmalloc_default_oom(size_t size) {
    fprintf(stderr, "zmalloc: Out of memory trying to allocate %zu bytes\n",
            size);
    fflush(stderr);
    abort();
}

static void (*malloc_oom_handler)(size_t) = zmalloc_default_oom;
static void (*socket_malloc_oom_handler)(size_t) = zmalloc_default_oom;

void malloc_set_oom_handler(void (*oom_handler)(size_t)) {
    malloc_oom_handler = oom_handler;
}

void socket_malloc_set_oom_handler(void (*oom_handler)(size_t)) {
    socket_malloc_oom_handler = oom_handler;
}

void *socket_malloc(int socket_id, size_t size) {
    void *ptr;
    if (socket_id < SOCKET_ID_ANY) {
        ptr = malloc(size);
        if (!ptr) malloc_oom_handler(size);
    } else {
        ptr = rte_malloc_socket(NULL, size, 0, socket_id);
        if (!ptr) socket_malloc_oom_handler(size);
    }
    return ptr;
}

void *socket_zmalloc(int socket_id, size_t size) {
    void *ptr;
    if (socket_id < SOCKET_ID_ANY) {
        ptr = calloc(1, size);
        if (!ptr) malloc_oom_handler(size);
    } else {
        ptr = rte_zmalloc_socket(NULL, size, 0, socket_id);
        if (!ptr) socket_malloc_oom_handler(size);
    }
    return ptr;
}

void *socket_calloc(int socket_id, size_t nmemb, size_t size) {
    return socket_zmalloc(socket_id, nmemb*size);
}

void *socket_realloc(int socket_id, void *ptr, size_t size) {
    if (socket_id < SOCKET_ID_ANY) {
        ptr = realloc(ptr, size);
        if (!ptr) malloc_oom_handler(size);
    } else {
        void *src = ptr;
        ptr = rte_zmalloc_socket(NULL, size, 0, socket_id);
        if (!ptr) socket_malloc_oom_handler(size);
        rte_memcpy(ptr, src, size);
    }
    return ptr;
}

void *socket_memdup(int socket_id, const void *ptr, size_t size) {
    void *p = socket_malloc(socket_id, size);
    rte_memcpy(p, ptr, size);
    return p;
}

void *socket_strdup(int socket_id, const char *s) {
    return socket_memdup(socket_id, s, strlen(s)+1);
}

void socket_free(int socket_id, void *ptr) {
    if (socket_id < SOCKET_ID_ANY)
        free(ptr);
    else
        rte_free(ptr);
}

