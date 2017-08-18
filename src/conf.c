/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * =======================================================================
 *       Filename:  conf.c
 *        Created:  2016-03-17 Thu 10:20
 *       Compiler:  gcc
 *
 *         Author:  Yu Yang
 *      	Email:  yyangplus@NOSPAM.gmail.com
 * =======================================================================
 */
#include "fmacros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>

#include "defines.h"
#include "str.h"
#include "conf.h"

#define SEP ' '

/* private functions */
static char *getKeyVal(char *buf, char *key);
static char *removeUseless(char *line);

int getLongVal(char *errstr, char *buf, char *entry, long *val) {
    char *end = NULL;
    long lval;
    char *str_val = getKeyVal(buf, entry);
    int base = 10;
    if (!str_val) {
        snprintf(errstr, ERR_STR_LEN, "no config for %s.", entry);
        return CONF_NX;
    }
    if (str_val[0] == '0') base = 16;
    lval = strtol(str_val, &end, base);
    if (*end == '\0') {
        *val = lval;
        return CONF_OK;
    } else {
        snprintf(errstr, ERR_STR_LEN, "invalid character for config %s", entry);
        return CONF_ERR;
    }
}

int getIntVal(char *errstr, char *buf, char *entry, int *val) {
    long lval = 0;
    int err = getLongVal(errstr, buf, entry, &lval);
    if (err == CONF_OK) {
        if (lval > INT_MAX || lval < INT_MIN) {
            snprintf(errstr, ERR_STR_LEN, "value is overflow for config %s.", entry);
            return CONF_ERR;
        }
        *val = (int) lval;
    }
    return err;
}

char *getStrVal(char *buf, char *entry, char *defaultVal) {
    char *val = getKeyVal(buf, entry);
    if (val) {
        val = strip(val, "\"");
        return strdup(val);
    } else {
        if (!defaultVal) return NULL;
        else return strdup(defaultVal );
    }
}

int getBoolVal(char *errstr, char *buf, char *entry, bool *val) {
    char *str_val = getKeyVal(buf, entry);
    if (!str_val) {
        snprintf(errstr, ERR_STR_LEN, "no config for %s.", entry);
        return CONF_NX;
    }
    if (!strcasecmp(str_val, "on") ||
        !strcasecmp(str_val, "yes") ||
        !strcasecmp(str_val, "true")) {
        *val = true;
        return CONF_OK;
    } else if (!strcasecmp(str_val, "off") ||
               !strcasecmp(str_val, "no") ||
               !strcasecmp(str_val, "false")) {
        *val = false;
        return CONF_OK;
    } else {
        snprintf(errstr, ERR_STR_LEN, "only on/true/yes and off/false/no is valid for the key %s.", entry);
        return CONF_ERR;
    }
}

int getStrArrayVal(char *errstr, char *buf, char *entry, char **ret, int *n) {
    char line[MAXLINE];
    char vdata[BUFSIZE] = "";
    size_t remain = BUFSIZE;
    bool found = false;
    char *open=NULL, *close=NULL;

    for (; sgets(line, MAXLINE, &buf) != NULL; ) {
        char *start = removeUseless(line);
        if (*start == 0) continue;

        char *middle = strchr(start, SEP);
        if (!middle) continue;
        *middle = '\0';
        middle++;
        char *name = strip(start, " ");
        if (strcasecmp(name, entry) == 0) {
            char *value = strip(middle, " ");
            open = strchr(value, '[');
            close = strchr(value, ']');
            if (!open) {
                snprintf(errstr, ERR_STR_LEN, "can't find '[' for entry: %s.", entry);
                return CONF_ERR;
            }
            *open = ' ';
            if (close) *close = 0;
            strncat(vdata, value, remain-1);
            remain -= strlen(value);
            if (remain <= 0) {
                snprintf(errstr, ERR_STR_LEN, "config is too long(more than %d characters.", BUFSIZE);
                return CONF_ERR;
            }
            found = true;
            break;
        }
    }
    if (found == false) {
        snprintf(errstr, ERR_STR_LEN, "can't find config for %s.", entry);
        return CONF_ERR;
    }
    if (close) goto ok;

    for (; sgets(line, MAXLINE, &buf) != NULL; ) {
        char *start = removeUseless(line);
        if (*start == 0) continue;

        close = strchr(start, ']');
        if (close) *close = 0;
        strncat(vdata, " ", remain-1);
        remain--;
        strncat(vdata, start, remain-1);
        remain -= strlen(start);
        if (remain <= 0) {
            snprintf(errstr, ERR_STR_LEN, "config is too long(more than %d characters.", BUFSIZE);
            return CONF_ERR;
        }
        if (close) goto ok;
    }
    snprintf(errstr, ERR_STR_LEN, "can't find ']' for entry for %s.", entry);
    return CONF_ERR;
ok:
    tokenize(vdata, ret, n, " \t");
    for (int i = 0; i < *n; i++) {
        ret[i] = strdup(ret[i]);
    }
    return CONF_OK;
}

/*!
 * read the config stays belong { and }
 *
 * @param buf : the whole config string
 * @param key : the name of the config
 * @param proc : callback used to handle a line.
 * @param privdata : this argument will be passed to callback.
 * @return
 */

int getBlockVal(char *errstr, char *buf, char *key, blockValProc *proc, void *privdata) {
    char line[MAXLINE];
    bool found = false;
    char *open=NULL, *close=NULL;
    char *tokens[64];
    int ntokens = 64;

    for (; sgets(line, MAXLINE, &buf) != NULL; ) {
        char *start = removeUseless(line);
        if (*start == 0) continue;

        char *middle = strchr(start, SEP);
        if (!middle) continue;
        *middle = '\0';
        middle++;
        char *name = strip(start, " ");
        if (strcasecmp(name, key) == 0) {
            char *value = strip(middle, " ");
            open = strchr(value, '{');
            close = strchr(value, '}');
            if (!open) {
                snprintf(errstr, ERR_STR_LEN, "cann't find '{' for %s config.", key);
                return CONF_ERR;
            }
            if (close) *close = 0;
            found = true;
            break;
        }
    }
    if (found == false) {
        snprintf(errstr, ERR_STR_LEN, "can't find config for %s.", key);
        return CONF_ERR;
    }
    if (close) return CONF_OK;

    for (; sgets(line, MAXLINE, &buf) != NULL; ) {
        char *start = removeUseless(line);
        if (*start == 0) continue;

        close = strchr(start, '}');
        if (close) return CONF_OK;
        tokenize(start, tokens, &ntokens, " \t");
        if (proc(errstr, ntokens, tokens, privdata) != CONF_OK) {
            return CONF_ERR;
        }
    }
    snprintf(errstr, ERR_STR_LEN, "Can't find '}' for %s config.", key);
    return CONF_ERR;
}

static char *getKeyVal(char *buf, char *key) {
    static char line[MAXLINE];
    for (; sgets(line, MAXLINE, &buf) != NULL; ) {
        char *start = removeUseless(line);
        if (*start == 0) continue;

        char *end = line + strlen(line);
        if (*(end - 1) == '\n') {
            *(end - 1) = '\0';
        }
        char *middle = strchr(start, SEP);

        if (!middle) {
            continue;
        }
        *middle = '\0';
        middle++;
        char *name = strip(start, " ");
        if (strcasecmp(name, key)) {
            continue;
        } else {
            char *value = strip(middle, " ");
            return value;
        }
    }
    return NULL;
}

static char *removeUseless(char *line) {
    removeComment(line, '#');
    return strip(line, " \n\t");
}

#if defined(CDNS_TEST)
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"
#include "testhelp.h"

#define UNUSED(x) (void)(x)

int confTest(int argc, char *argv[]) {
    char errstr[ERR_STR_LEN];
    int err;
    int iv;
    bool bv;

    if (argc < 4) {
        fprintf(stderr, "need conf file");
        exit(1);
    }
    char *fp = readFile(argv[3]);
    test_cond("loglevel: ", strcmp(getStrVal(fp, "loglevel", ""), "info") == 0);
    test_cond("logfile: ", strcmp(getStrVal(fp, "logfile", ""), "") == 0);
    test_cond("pidfile: ", strcmp(getStrVal(fp, "pidfile", ""), "/var/run/cdns_53.pid") == 0);

    iv = 0;
    getIntVal(errstr, fp, "port", &iv);
    test_cond("port: ", iv == 53);

    bv = true;
    getBoolVal(errstr, fp, "daemonize", &bv);
    test_cond("daemonize: ", bv == false);
    {
        char *results[512];
        int n = 512;
        err = getStrArrayVal(errstr, fp, "bind", results, &n);
        fprintf(stderr, "getStrArrayVal: %d\n", err);
        test_cond("bind count: ", n == 3);
        test_cond("bind content(1): ", strcmp(results[0], "127.0.0.1") == 0);
        test_cond("bind content(2): ", strcmp(results[1], "::1") == 0);
        test_cond("bind content(3): ", strcmp(results[2], "::126") == 0);
    }
    test_report();
    return 0;
}
#endif
