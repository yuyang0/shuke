//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-04-01
//

#ifndef _DEFINES_H_
#define _DEFINES_H_ 1

#include <stddef.h>

#define MAXLINE 1024
#define BUFSIZE 4096
#define ERR_STR_LEN 256

#define UNUSED(x) (void)(x)
#define UNUSED2(x1, x2) (void)(x1), (void)(x2)
#define UNUSED3(x1, x2, x3) (void)(x1), (void)(x2), (void)(x3)

#define MIN(x1, x2) (x1) < (x2)? (x1): (x2)
#define MAX(x1, x2) (x1) > (x2)? (x1): (x2)

#define OK_CODE      0
#define ERR_CODE    (-1)
#define EOF_CODE    (-2)
#define NO_MEM_CODE (-3)

/**
 * sk_container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define sk_container_of(ptr, type, member) ({ \
     const typeof( ((type *)0)->member ) *__mptr = (ptr); \
     (type *)( (char *)__mptr - offsetof(type,member) );})

#endif /* _DEFINES_H_ */
