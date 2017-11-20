//
// Created by yangyu on 17-3-29.
//

#ifndef SHUKE_UTILS_H
#define SHUKE_UTILS_H

#include <stdbool.h>

void freev(void **pp);

long long ustime(void);
long long mstime(void);
void sortIntArray(int arr[], size_t nitems);
int intArrayToStr(int arr[], int nitems, char *seps, char *buf, size_t size);
int str2long(char *ss, long *v);
void bytesToHuman(char *s, unsigned long long n);
void numberToHuman(char *s, unsigned long long n);

char* readFile(const char *fname);
char *zreadFile(const char *filename);
char *toAbsPath(char *p, char *rootp);
char *getHomePath(void);

size_t lenlabellen(char *domain);

static inline bool isEmptyStr(char *ss) {
    return (ss == NULL) || (ss[0] == 0);
}

int snpack(char *buf, int offset, size_t size, char const *fmt, ...);

#endif //SHUKE_UTILS_H
