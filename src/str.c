//
// Created by yangyu on 17-1-17.
//
#include "fmacros.h"

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "str.h"

/* return true if the string contain the character
   otherwise return false
 */
static inline bool contain_char(char *s, char c) {
    return strchr(s, c) != NULL;
}

char *strnstr(char *haystack, char *needle, size_t n) {
    size_t i;
    char *p = haystack;
    for (i = 0; i < n; ++i) {
        if (startswith(p, needle)) {
            return p;
        } else {
            p++;
        }
    }
    return NULL;
}

bool startswith(const char *str, const char *prefix) {
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

bool endswith(const char *str, const char *suffix) {
    const char *p = str + (strlen(str) - strlen(suffix));
    if (p < str) return false;
    return strcmp(p, suffix) == 0;
}

bool startscasewith(const char *str, const char *prefix) {
    return strncasecmp(str, prefix, strlen(prefix)) == 0;
}

bool endscasewith(const char *str, const char *suffix) {
    const char *p = str + (strlen(str) - strlen(suffix));
    if (p < str) return false;
    return strcasecmp(p, suffix) == 0;
}

/*strip the characters contained in d_chars
  at the beginning of the string
*/
char *lstrip(char *str, char *d_chars) {
    for (; *str; ++str) {
        char c = *str;
        if (!contain_char(d_chars, c)) {
            break;
        }
    }
    return str;
}

char *rstrip(char *str, char *d_chars) {
    char *end = str + strlen(str) - 1;
    for (; end >= str; --end) {
        if (!contain_char(d_chars, *end)) {
            break;
        }
    }
    *(++end) = '\0';
    return str;
}

char *strip(char *str, char *d_chars) {
    char *start = lstrip(str, d_chars);
    return rstrip(start, d_chars);
}

/*!
 * split str to parts
 *
 * @param str
 * @param seps : separator characters.
 * @param ret : the parts array
 * @param n : store the max size of ret by caller and return the size of parts to caller.
 *            pls note: the value of n returned by this function maybe bigger than the size of ret,
 *                      in this case, n is the desired size.
 * @return 0 if everything is ok, -1 if ret is not enough
 */
int strsplit(char *str, char *seps, char **ret, int *n) {
    int max = *n;
    char *start = str;
    char *maxEnd = str + strlen(str);
    int i;
    for (*n = 0, i =0 ; i < max && start < maxEnd; ++i ) {
        for ( ; contain_char(seps, *start) && *start != 0; start++) ;
        if (*start == 0) break;
        if (i < max) ret[i] = start;
        (*n)++;
        for ( ; !contain_char(seps, *start) && *start != 0; start++) ;
        if (*start == 0) break;
        if (i < max) *start = '\0';
        start++;
    }
    if (*n > max) return -1;
    else return 0;
}

/*!
 * tokenize the string, support literal string and escape
 *
 * @param str : the raw string
 * @param ret : the result token array
 * @param n : store the max size of ret by caller and return real size of ret to caller.
 * @return : 0 for success, -1 for ret size is not enough, -2 for syntax error(unbalanced literal string)
 */
int tokenize(char *str, char **ret, int *n, char *seps) {
    char *start = str, *end = NULL;
    int max = *n;
    char *maxEnd = str + strlen(str);
    bool literal = false;
    *n = 0;

    while (start < maxEnd) {
        // skip the useless characters at the start.
        for ( ; contain_char(seps, *start) && start < maxEnd; start++) ;
        end = start;
        if (end >= maxEnd) return 0;
        if (*n >= max) {
            return -1;
        }
        for (; end < maxEnd; end++) {
            if (*end == '\\') {
                end++;
                continue;
            }
            if (*end == '"') {
                if (literal) literal = false;
                else literal = true;
                continue;
            }
            if (literal) continue;
            if (contain_char(seps, *end)) break;
        }
        if (literal == true) return -2;
        if (end > maxEnd) end = maxEnd;
        *end = '\0';
        ret[(*n)++] = start;
        start = end + 1;
    }
    return 0;
}

/*!
 * remove the comment at the end of ss, manly used to parse the conf file
 *
 * @param ss : the string
 * @param cmt_char : the start character of the comment
 */
void removeComment(char *ss, char cmt_char) {
    char *end = ss + strlen(ss);
    bool literal = false;
    for( ; end >= ss; end--) {
        if (*end == '\\') {
            end--;
            continue;
        }
        if (*end == '"') {
            if (literal) literal = false;
            else literal = true;
            continue;
        }
        if (literal) continue;
        if (*end == cmt_char) {
            *end = 0;
            return;
        }
    }
}

char *strtolower(char *str) {
    char *ret = str;
    while(*str) {
        if(*str >= 65 && *str <= 90)
            *str |= 32;
        str++;
    }
    return ret;
}

char *strtoupper(char *str) {
    char *ret = str;
    while(*str) {
        if (*str >= 97 && *str <= 122)
            *str &= (~32);
        str++;
    }
    return ret;
}

size_t strcountchr(char *str, char c) {
    size_t count = 0;
    while (*str) {
        if (*str == c)
            count++;
        str++;
    }
    return count;
}

size_t strcountstr(char *str, char *fstr) {
    size_t count = 0;
    while (*str) {
        if (startswith(str, fstr)) {
            count++;
            str += strlen(fstr);
            continue;
        }
        str++;
    }
    return count;
}

// convert ipv4 address to binary form, `val` should be a 4 byte buffer.
// return true if the format of the address is valid, otherwise return false
bool str2ipv4(const char *src, void *dst) {
    /* uint32_t tv[4] = {0}, idx = 0; */
    /* size_t i, n = strlen(addr); */
    /* for (i = 0; i < n; i++) { */
    /*     if (addr[i] >= '0' && addr[i] <= '9') */
    /*         tv[idx] = tv[idx] * 10 + addr[i] - '0'; */
    /*     else { */
    /*         idx++; */
    /*         if (addr[i] != '.' || idx == 4)     //format error */
    /*         { */
    /*             *val = 0; */
    /*             return false; */
    /*         } */
    /*     } */
    /* } */
    /* for (i = 0; i < 4; i++) { */
    /*     if (tv[i] > 255) return false; */
    /*     val[i] = (char)(tv[i]); */
    /* } */
    /* return true; */
    return inet_pton(AF_INET, src, dst) == 1;
}

// convert ipv6 address to binary form, `val` should be a 16 byte buffer.
bool str2ipv6(const char *src, void *dst) {
    return inet_pton(AF_INET6, src, dst) == 1;
}

int dot2lenlabel(char *human, char *label) {
    char *dest = label;
    if (dest == NULL) dest = human;
    size_t totallen = strlen(human);
    *(dest + totallen) = 0;
    char *prev = human + totallen - 1;
    char *src = human + totallen - 2;
    dest = dest + totallen - 1;

    for (; src >= human; src--, dest--) {
        if (*src == '.') {
            *dest = (uint8_t) (prev - src - 1);
            prev = src;
        } else {
            *dest = *src;
        }
    }
    *dest = (uint8_t) (prev - src - 1);
    return 0;
}

int len2dotlabel(char *label, char *human) {
    char *src = label;
    char *dest = human;
    if (dest == NULL) dest = label;

    uint8_t len = (uint8_t) (*src);
    do {
        src++;
        int j;
        for (j = 0; j < len; ++j) *dest++ = *src++;
        *dest++ = '.';
        len = (uint8_t) (*src);
    } while(len > 0);

    *dest = '\0';
    return 0;
}

/*!
 * like fgets, but instead of reading line from file, this function read a line from buf.
 * @param s
 * @param size
 * @param bufp
 * @return
 */
char *sgets(char *s, int size, char **bufp) {
    int len;
    char *buf = *bufp;
    char *next = strchr(buf, '\n');
    if (next == NULL) next = buf + strlen(buf);
    else next++;

    len = (int)(next - buf);
    if (len >= size) len = size-1;
    if (len == 0) return NULL;
    memcpy(s, buf, len);
    s[len] = 0;
    *bufp = buf + len;
    return s;
}

#if defined(CDNS_TEST)

#include <stdio.h>
#include <stdlib.h>
#include "testhelp.h"

#define UNUSED(x) (void)(x)

int strTest(int argc, char *argv[]) {
    UNUSED(argc);
    UNUSED(argv);
    {
        char buf[] = "hElLo wOrlD A z A z $ # & * 1 )";
        char buf_low[] = "hello world a z a z $ # & * 1 )";
        test_cond("string to lower",
                  strcmp(buf_low, strtolower(buf)) == 0);
    }

    {
        char buf[] = "hElLo wOrlD A z A z $ # & * 1 )";
        char buf_upp[] = "HELLO WORLD A Z A Z $ # & * 1 )";
        test_cond("string to upper",
                  strcmp(buf_upp, strtoupper(buf)) == 0);
    }

    {
        char buf[] = " %   hello world   ";
        test_cond("left strip space",
                  strcmp(lstrip(buf, " %"), "hello world   ") == 0)
    }
    {
        char buf[] = "    hello world   ";
        test_cond("strip space",
                  strcmp(strip(buf, " "), "hello world") == 0)
    }

    {
        char buf[] = "  = & aa = &bb = & =  =";
        test_cond("left strip special char",
                  strcmp(lstrip(buf, " =&"), "aa = &bb = & =  =") == 0)
        test_cond("strip space special char",
                  strcmp(strip(buf, " =&"), "aa = &bb") == 0)
    }

    test_cond("startswith1: ",startswith("hello", "hel1") == false);
    test_cond("startswith2: ",startswith("", "hell") == false);
    test_cond("startswith3: ",startswith("hello", "hell") == true);
    test_cond("startswith4: ",startswith("hello", "hello") == true);
    test_cond("startswith5: ",startswith("hello", "hello ") == false);
    test_cond("endswith1: ",endswith("hello", "ello") == true);
    test_cond("endswith2: ",endswith("", "") == true);
    test_cond("endswith3: ",endswith("", "hell") == false);

    test_cond("startscasewith",startscasewith("HeLlo", "hEll") == true);
    test_cond("endscasewith",endscasewith("HeLlo", "hEllO") == true);

    test_cond("strcasestr: ",strcasestr("wHO Are YOU", " aRe you") != NULL);
    {
        char buf[] = " \taa bb\ncc\tdd \nee";
        char *ret[10];
        int n = 10;
        strsplit(buf, " \t\n", ret, &n);
        test_cond("strsplit: ", n == 5);
        test_cond("strsplit: ", strcmp(ret[0], "aa") == 0 && \
                  strcmp(ret[1], "bb") == 0 && \
                  strcmp(ret[2], "cc") == 0 && \
                  strcmp(ret[3], "dd") == 0 && \
                  strcmp(ret[4], "ee") == 0);
    }
    {
        char buf[] = "127.0.0.1";
        char ipv4[4];
        str2ipv4(buf, ipv4);
        test_cond("str2ipv4, 1: ", ipv4[0]==127 && ipv4[1]==0 && ipv4[2]==0 && ipv4[3]==1);

        char buf2[] = "256.111.257.234";
        test_cond("str2ipv4, 2: ", str2ipv4(buf2, ipv4) == false);
    }

    {
        unsigned char buf[] = "1234::abcd";
        unsigned char ipv6[16] = {0};
        test_cond("str2ipv6 1: ", str2ipv6((char *)buf, (char *)ipv6) == true);
        test_cond("str2ipv6 2: ", ipv6[0]==0x12 && ipv6[1]==0x34 && ipv6[2] == 0 && ipv6[14]==0xab && ipv6[15] == 0xcd);
        /* printf("%0x, %0x, %0x, %0x\n", ipv6[0], ipv6[1], ipv6[14], ipv6[15]); */
    }
    {
        char buf[] = "www.baidu.com.";
        // use dirty data to make sure the string ends with zero
        char data[512] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        dot2lenlabel(buf, data);
        test_cond("dot2lenlabel 1: ", strcmp(data, "\3www\5baidu\3com") == 0);
        printf("%s\n", data);
        dot2lenlabel(buf, NULL);
        test_cond("dot2lenlabel 2: ", strcmp(buf, "\3www\5baidu\3com") == 0);

        char root[] = ".";
        dot2lenlabel(root, NULL);
        test_cond("dot2lenlabel 3: ", strlen(root) == 0);
        char label[] = "www.";
        dot2lenlabel(label, NULL);
        test_cond("dot2lenlabel 4: ", strcmp(label, "\3www") == 0);
    }
    {
        char buf[] = "\3www\5baidu\3com";
        char data[512] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        len2dotlabel(buf, data);
        test_cond("len2dotlabel 1: ", strcmp(data, "www.baidu.com.") == 0);

        len2dotlabel(buf, NULL);
        test_cond("len2dotlabel 2: ", strcmp(buf, "www.baidu.com.") == 0);

        char empty[2] = {0};
        len2dotlabel(empty, NULL);
        test_cond("len2dotlabel 3: ", strcmp(empty, ".") == 0);
    }
    {
        char ss[] = " \t aa bb 123 \"cc dd ff \" gg ";
        char *ret[10];
        int n = 10;
        tokenize(ss, ret, &n);
        test_cond("tokenize", n == 5);
        test_cond("tokenize", strcmp(ret[0], "aa") == 0);
        test_cond("tokenize", strcmp(ret[1], "bb") == 0);
        test_cond("tokenize", strcmp(ret[3], "\"cc dd ff \"") == 0);
        test_cond("tokenize", strcmp(ret[4], "gg") == 0);

    }
    test_report();
    return 0;
}
#endif
