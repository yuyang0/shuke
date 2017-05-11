//
// Created by yangyu on 17-3-29.
//

#ifndef CDNS_UTILS_H
#define CDNS_UTILS_H

char* readFile(const char *fname);
char *toAbsPath(char *p, char *rootp);
char *getHomePath(void);

size_t lenlabellen(char *domain);
#endif //CDNS_UTILS_H
