//
// Created by yangyu on 17-7-6.
//

#ifndef SHUKE_SHUKEASSERT_H
#define SHUKE_SHUKEASSERT_H

#include <unistd.h>  // for _exit
#include "rte_branch_prediction.h"

#define assert(_e)                              \
    do{                                         \
        if (unlikely(!(_e))) {                  \
            _shukeAssert(#_e,__FILE__,__LINE__); \
            _exit(1);                           \
        }                                       \
    } while(0)

void _shukeAssert(char *estr, char *file, int line);

#endif //SHUKE_SHUKEASSERT_H
