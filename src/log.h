//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-11
//

#ifndef _LOG_H_
#define _LOG_H_ 1

#include <time.h>
#include <sys/time.h>

#include <rte_log.h>

#define RTE_LOG_DP_LEVEL RTE_LOG_DEBUG

static inline int __rte_log(uint32_t level, uint32_t logtype, const char *tstr, const char *lstr, const char *fmt, ...) {
    if ((level > rte_logs.level) || !(logtype & rte_logs.type))
        return 0;

    char format[1024];
    int ret;
    size_t off;
    struct timeval tv;
    gettimeofday(&tv,NULL);
    off = strftime(format, 1024, "%Y/%m/%d %H:%M:%S.",localtime(&tv.tv_sec));
    snprintf(format+off, 1024-off,"%03d %s %s%s\n", (int)tv.tv_usec/1000, tstr, lstr, fmt);

    va_list ap;
    va_start(ap, fmt);

    ret = rte_vlog(level, logtype, format, ap);

    va_end(ap);
    return ret;
}

#define LOG_DEBUG(t, ...)                                          \
    (void)((RTE_LOG_DEBUG <= RTE_LOG_DP_LEVEL)?                         \
           __rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_ ## t, #t, "[debug]: ", ##__VA_ARGS__): \
           0)

#define LOG_INFO(t, ...)                                           \
    __rte_log(RTE_LOG_INFO, RTE_LOGTYPE_ ## t, #t, "[info]: ", ##__VA_ARGS__)

#define LOG_NOTICE(t, ...)                                         \
    __rte_log(RTE_LOG_NOTICE, RTE_LOGTYPE_ ## t, #t, "[notice]: ", ##__VA_ARGS__)

#define LOG_WARNING(t, ...)                                        \
    __rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_ ## t, #t, "[warn]: ", ##__VA_ARGS__)

#define LOG_WARN(t, ...)                                           \
    __rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_ ## t, #t, "[warn]: ", ##__VA_ARGS__)

#define LOG_ERR(t, ...)                                          \
    __rte_log(RTE_LOG_ERR, RTE_LOGTYPE_ ## t, #t, "[err]: ", ##__VA_ARGS__)

#define LOG_ERROR LOG_ERR

#define LOG_FATAL(t, ...)                                          \
    __rte_log(RTE_LOG_ERR, RTE_LOGTYPE_ ## t, #t, "[err]: ", ##__VA_ARGS__); abort()

#define LOG_RAW(l, t, ...)    \
    rte_log(RTE_LOG_ ## l, RTE_LOGTYPE_ ## t, __VA_ARGS__)

#endif /* _LOG_H_ */
