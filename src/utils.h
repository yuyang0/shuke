//
// Created by yangyu on 17-3-29.
//

#ifndef CDNS_UTILS_H
#define CDNS_UTILS_H

#include <stdbool.h>

char* readFile(const char *fname);
char *toAbsPath(char *p, char *rootp);
char *getHomePath(void);

size_t lenlabellen(char *domain);

static inline bool isEmptyStr(char *ss) {
    if (ss == NULL) return true;
    return ss[0] == 0;
}

#endif //CDNS_UTILS_H
