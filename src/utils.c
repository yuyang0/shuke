//
// Created by yangyu on 17-3-29.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "utils.h"

char* readFile(const char *filename) {
    char *buffer = NULL;
    int string_size, read_size;
    FILE *handler = fopen(filename, "r");

    if (handler) {
        // Seek the last byte of the file
        fseek(handler, 0, SEEK_END);
        // Offset from the first to the last byte, or in other words, filesize
        string_size = ftell(handler);
        // go back to the start of the file
        rewind(handler);

        // Allocate a string that can hold it all
        buffer = (char *) malloc(sizeof(char) * (string_size + 1));

        // Read it all in one operation
        read_size = fread(buffer, sizeof(char), string_size, handler);

        // fread doesn't set it so put a \0 in the last position
        // and buffer is now officially a string
        buffer[string_size] = '\0';

        if (string_size != read_size) {
            // Something went wrong, throw away the memory and set
            // the buffer to NULL
            free(buffer);
            buffer = NULL;
        }

        // Always remember to close the file.
        fclose(handler);
    }
    return buffer;
}

char* getHomePath(void)
{
    char *home = getenv("HOME");
    if (home) return home;
    struct passwd *pw = getpwuid(getuid());
    return pw->pw_dir;
}

char *toAbsPath(char *p, char *rootp) {
    char buf[4096] = "";
    char root[1024];
    if (rootp == NULL) {
        if (getcwd(root, 1024) == NULL) return NULL;
    } else {
        snprintf(root, 1024, "%s", rootp);
    }

    char *end = p + strlen(p) - 1;
    char *ptr = p;
    if (*p == '/') return strdup(p);
    if (*p == '~') {
        char *home = getHomePath();
        p += 2;
        snprintf(buf, 4096, "%s/%s", home, p);
        return strdup(buf);
    }

    if (*end == '/') *end = 0;
    if (*ptr == '.') {
        while (*ptr == '.') {
            if (*ptr == '.' && *(ptr+1) == '.') {
                end = strrchr(root, '/');
                *end = 0;
                if (*(ptr+2) == '/') {
                    ptr += 3;
                }
            } else {
                if (*(ptr+1) == '/') {
                    ptr += 2;
                }
            }
            snprintf(buf, 4096, "%s/%s", root, ptr);
        }
    } else {
        snprintf(buf, 4096, "%s/%s", root, p);
    }
    return strdup(buf);
}

/*!
 * get length of the domain in <len label> format
 * @param domain : the domain name in <len label> format.
 * @return the length of the domain
 */
size_t lenlabellen(char *domain) {
    char *ptr;
    for (ptr = domain; *ptr != 0; ptr += (*ptr+1)) ;
    return ptr - domain;
}
