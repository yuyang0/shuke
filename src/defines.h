//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-04-01
//

#ifndef _DEFINES_H_
#define _DEFINES_H_ 1

#define MAXLINE 1024
#define BUFSIZE 4096
#define ERR_STR_LEN 256

#define UNUSED(x) (void)(x)
#define UNUSED2(x1, x2) (void)(x1), (void)(x2)
#define UNUSED3(x1, x2, x3) (void)(x1), (void)(x2), (void)(x3)

#define MIN(x1, x2) (x1) < (x2)? (x1): (x2)
#define MAX(x1, x2) (x1) > (x2)? (x1): (x2)

#define ERR_CODE -1
#define OK_CODE   0
#define EOF_CODE  1

#endif /* _DEFINES_H_ */
