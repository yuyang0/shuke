//
// Created by yangyu on 17-3-29.
//

#ifndef CDNS_UTILS_H
#define CDNS_UTILS_H

#include <stdbool.h>

long long ustime(void);
long long mstime(void);
void bytesToHuman(char *s, unsigned long long n);

char* readFile(const char *fname);
char *toAbsPath(char *p, char *rootp);
char *getHomePath(void);

size_t lenlabellen(char *domain);

static inline bool isEmptyStr(char *ss) {
    return (ss == NULL) || (ss[0] == 0);
}

int snpack(char *buf, int offset, size_t size, char const *fmt, ...);

#endif //CDNS_UTILS_H
