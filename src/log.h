//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-11
//

#ifndef _LOG_H_
#define _LOG_H_ 1

#define LOG_DEBUG(t, fmt, ...)                                          \
    (void)((RTE_LOG_DEBUG <= RTE_LOG_DP_LEVEL)?                         \
           rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_ ## t, fmt "\n", ##__VA_ARGS__): \
           0)

#define LOG_INFO(t, fmt, ...)                                           \
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_ ## t, fmt "\n", ##__VA_ARGS__)

#define LOG_NOTICE(t, fmt, ...)                                         \
    rte_log(RTE_LOG_NOTICE, RTE_LOGTYPE_ ## t, fmt "\n", ##__VA_ARGS__)

#define LOG_WARNING(t, fmt, ...)                                        \
    rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_ ## t, fmt "\n", ##__VA_ARGS__)

#define LOG_WARN(t, fmt, ...)                                           \
    rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_ ## t, fmt "\n", ##__VA_ARGS__)

#define LOG_ERR(t, fmt, ...)                                          \
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_ ## t, fmt "\n", ##__VA_ARGS__)


#endif /* _LOG_H_ */
