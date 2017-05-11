//
// Created by yangyu on 17-1-17.
//

#ifndef CDNS_STR_H
#define CDNS_STR_H

#include <stdbool.h>

char *strnstr(char *haystack, char *needle, size_t n);
bool startswith(const char *, const char *);
bool endswith(const char *, const char *);
bool startscasewith(const char *, const char *);
bool endscasewith(const char *, const char *);


char *lstrip(char *str, char *d_chars);
char *rstrip(char *str, char *d_chars);
char *strip(char *str, char *d_chars);

char *strtolower(char *str);
char *strtoupper(char *str);

size_t strcountchr(char *str, char c);
size_t strcountstr(char *str, char *fstr);

int strsplit(char *str, char *seps, char **ret, int *n);
int tokenize(char *str, char **ret, int *n);

bool str2ipv4(const char *addr, char *val);
bool str2ipv6(char *addr, char *val);

int dot2lenlabel(char *human, char *label);
int len2dotlabel(char *label, char *human);

char *sgets(char *s, int size, char **bufp);
void removeComment(char *ss, char cmt_char);

#if defined(CDNS_TEST)
int strTest(int argc, char *argv[]);
#endif

#endif //CDNS_STR_H
