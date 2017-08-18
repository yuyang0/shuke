/*
 * ==================================================================
 *       Filename:  conf.h
 *        Created:  2016-03-17 Thu 10:40
 *       Compiler:  gcc
 *
 *         Author:  Yu Yang
 *    	    Email:  yyangplus@NOSPAM.gmail.com
 * ==================================================================
 */

#ifndef _CONF_H_
#define _CONF_H_ 1

#include <stdio.h>
#include <stdbool.h>

#define CONF_OK    0
#define CONF_ERR  -1
#define CONF_NX   -2    // not exist

typedef int blockValProc(char *errstr, int argc, char *argv[], void *privdata);
#define CHECK_CONFIG(name, exp, msg)                                    \
    do{                                                                 \
        if (!(exp)) {                                                   \
            char *temp = msg;                                           \
            if (temp) fprintf(stderr, "%s\n", temp);                    \
            else fprintf(stderr, "Config Error: invalid value for %s config\n", name); \
            exit(1);                                                    \
        }                                                               \
    }while(0)

// used to check config which can be ignored
#define CHECK_CONF_ERR(err, errstr)                         \
    do {                                                    \
        if ((err) == CONF_ERR) {                            \
            fprintf(stderr, "Config Error: %s.\n", errstr); \
            exit(1);                                        \
        }                                                   \
    } while(0)

// used to check config which can't be ignored(don't allow default value)
#define CHECK_CONF_NOT_OK(err, errstr)                      \
    do {                                                    \
        if ((err) != CONF_OK) {                             \
            fprintf(stderr, "Config Error: %s.\n", errstr); \
            exit(1);                                        \
        }                                                   \
    } while(0)


int getLongVal(char *errstr, char *buf, char *entry, long *val);
int getIntVal(char *errstr, char *buf, char *entry, int *val);
char *getStrVal(char *buf, char *entry, char *defaultVal);

int getBoolVal(char *errstr, char *buf, char *entry, bool *val);
int getStrArrayVal(char *errstr, char *buf, char *entry, char **ret, int *n);
int getBlockVal(char *errstr, char *buf, char *key, blockValProc *proc, void *privdata);

#if defined(SK_TEST)
int confTest(int argc, char *argv[]);
#endif
#endif /* _CONF_H_ */
