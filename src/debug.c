//
// Created by yangyu on 17-7-6.
//
#include "shuke.h"

#include <arpa/inet.h>
#include <signal.h>

#include <execinfo.h>
#include <ucontext.h>
#include <fcntl.h>

DEF_LOG_MODULE(RTE_LOGTYPE_USER1, "DBG");

/* =========================== Crash handling  ============================== */
void _shukeAssert(char *estr, char *file, int line) {
    LOG_WARN("=== ASSERTION FAILED ===\n"
             "==> %s:%d '%s' is not true\n"
             "(forcing SIGSEGV to print the bug report.)",
             file,line,estr);
    *((char*)-1) = 'x';
}

void _shukePanic(char *msg, char *file, int line) {
    LOG_WARN("------------------------------------------------\n"
             "!!! Software Failure. Press left mouse button to continue\n"
             "Guru Meditation: %s #%s:%d\n"
             "(forcing SIGSEGV in order to print the stack trace)\n"
             "------------------------------------------------",
             msg,file,line);
    *((char*)-1) = 'x';
}

static void *getMcontextEip(ucontext_t *uc) {
#if defined(__APPLE__) && !defined(MAC_OS_X_VERSION_10_6)
    /* OSX < 10.6 */
    #if defined(__x86_64__)
    return (void*) uc->uc_mcontext->__ss.__rip;
    #elif defined(__i386__)
    return (void*) uc->uc_mcontext->__ss.__eip;
    #else
    return (void*) uc->uc_mcontext->__ss.__srr0;
    #endif
#elif defined(__APPLE__) && defined(MAC_OS_X_VERSION_10_6)
    /* OSX >= 10.6 */
    #if defined(_STRUCT_X86_THREAD_STATE64) && !defined(__i386__)
    return (void*) uc->uc_mcontext->__ss.__rip;
    #else
    return (void*) uc->uc_mcontext->__ss.__eip;
    #endif
#elif defined(__linux__)
    /* Linux */
    #if defined(__i386__)
    return (void*) uc->uc_mcontext.gregs[14]; /* Linux 32 */
    #elif defined(__X86_64__) || defined(__x86_64__)
    return (void*) uc->uc_mcontext.gregs[16]; /* Linux 64 */
    #elif defined(__ia64__) /* Linux IA64 */
    return (void*) uc->uc_mcontext.sc_ip;
    #endif
#else
    return NULL;
#endif
}

void logStackContent(void **sp, char *buf, size_t size) {
    int i, n;
    for (i = 15; i >= 0; i--) {
        unsigned long addr = (unsigned long) sp+i;
        unsigned long val = (unsigned long) sp[i];

        if (sizeof(long) == 4)
            n = snprintf(buf, size, "(%08lx) -> %08lx  \n", addr, val);
        else
            n = snprintf(buf, size, "(%016lx) -> %016lx  \n", addr, val);
        buf += n;
        size -= n;
        if (n <= 0) break;
    }
}

void registersToStr(ucontext_t *uc, char *buf, size_t size) {
    int n;
/* Linux */
#if defined(__linux__)
    /* Linux x86 */
    #if defined(__i386__)
    n = snprintf(buf, size,
    "\n"
    "EAX:%08lx EBX:%08lx ECX:%08lx EDX:%08lx\n"
    "EDI:%08lx ESI:%08lx EBP:%08lx ESP:%08lx\n"
    "SS :%08lx EFL:%08lx EIP:%08lx CS:%08lx\n"
    "DS :%08lx ES :%08lx FS :%08lx GS:%08lx\n",
        (unsigned long) uc->uc_mcontext.gregs[11],
        (unsigned long) uc->uc_mcontext.gregs[8],
        (unsigned long) uc->uc_mcontext.gregs[10],
        (unsigned long) uc->uc_mcontext.gregs[9],
        (unsigned long) uc->uc_mcontext.gregs[4],
        (unsigned long) uc->uc_mcontext.gregs[5],
        (unsigned long) uc->uc_mcontext.gregs[6],
        (unsigned long) uc->uc_mcontext.gregs[7],
        (unsigned long) uc->uc_mcontext.gregs[18],
        (unsigned long) uc->uc_mcontext.gregs[17],
        (unsigned long) uc->uc_mcontext.gregs[14],
        (unsigned long) uc->uc_mcontext.gregs[15],
        (unsigned long) uc->uc_mcontext.gregs[3],
        (unsigned long) uc->uc_mcontext.gregs[2],
        (unsigned long) uc->uc_mcontext.gregs[1],
        (unsigned long) uc->uc_mcontext.gregs[0]
    );
    logStackContent((void**)uc->uc_mcontext.gregs[7], buf+n, size-n);
    #elif defined(__X86_64__) || defined(__x86_64__)
    /* Linux AMD64 */
    n = snprintf(buf, size,
    "\n"
    "RAX:%016lx RBX:%016lx\nRCX:%016lx RDX:%016lx\n"
    "RDI:%016lx RSI:%016lx\nRBP:%016lx RSP:%016lx\n"
    "R8 :%016lx R9 :%016lx\nR10:%016lx R11:%016lx\n"
    "R12:%016lx R13:%016lx\nR14:%016lx R15:%016lx\n"
    "RIP:%016lx EFL:%016lx\nCSGSFS:%016lx\n",
        (unsigned long) uc->uc_mcontext.gregs[13],
        (unsigned long) uc->uc_mcontext.gregs[11],
        (unsigned long) uc->uc_mcontext.gregs[14],
        (unsigned long) uc->uc_mcontext.gregs[12],
        (unsigned long) uc->uc_mcontext.gregs[8],
        (unsigned long) uc->uc_mcontext.gregs[9],
        (unsigned long) uc->uc_mcontext.gregs[10],
        (unsigned long) uc->uc_mcontext.gregs[15],
        (unsigned long) uc->uc_mcontext.gregs[0],
        (unsigned long) uc->uc_mcontext.gregs[1],
        (unsigned long) uc->uc_mcontext.gregs[2],
        (unsigned long) uc->uc_mcontext.gregs[3],
        (unsigned long) uc->uc_mcontext.gregs[4],
        (unsigned long) uc->uc_mcontext.gregs[5],
        (unsigned long) uc->uc_mcontext.gregs[6],
        (unsigned long) uc->uc_mcontext.gregs[7],
        (unsigned long) uc->uc_mcontext.gregs[16],
        (unsigned long) uc->uc_mcontext.gregs[17],
        (unsigned long) uc->uc_mcontext.gregs[18]
    );
    logStackContent((void**)uc->uc_mcontext.gregs[15], buf+n, size-n);
    #endif
#else
    snprintf(buf, size,
        "  Dumping of registers not supported for this OS/arch\n");
#endif
}

/* Logs the stack trace using the backtrace() call. This function is designed
 * to be called from signal handlers safely. */
void logStackTrace(ucontext_t *uc) {
    void *trace[100];
    int trace_size = 0, fd;

    /* Open the log file in append mode. */
    fd = fileno(sk.log_fp);
    if (fd == -1) return;

    /* Generate the stack trace */
    trace_size = backtrace(trace, 100);

    /* overwrite sigaction with caller's address */
    if (getMcontextEip(uc) != NULL)
        trace[1] = getMcontextEip(uc);

    /* Write symbols to log file */
    backtrace_symbols_fd(trace, trace_size, fd);

    /* Cleanup */
    // if (!log_to_stdout) close(fd);
}

void sigsegvHandler(int sig, siginfo_t *info, void *secret) {
    ucontext_t *uc = (ucontext_t*) secret;
    struct sigaction act;
    char regbuf[4096];
    char segbuf[1024] = "";

    if (sig == SIGSEGV) {
        snprintf(segbuf, 1024,
                 "    SIGSEGV caused by address: %p\n", (void*)info->si_addr);
    }

    /* Log dump of processor registers */
    registersToStr(uc, regbuf, 4096);

    LOG_WARN(
            "\n======================\n"
            "    SHUKE %s crashed by signal: %d\n"
            "%s"
            "--- REGISTERS\n"
            "%s\n"
            "--- STACK TRACE\n",
            SHUKE_VERSION, sig,
            segbuf,
            regbuf
    );
    /*
     * in multiple thread environment, this is not good way, but I didn't find better solution.
     */
    fflush(sk.log_fp);
    /* Log the stack trace */
    logStackTrace(uc);

    // rte_dump_registers();
    // rte_dump_stack();
    /* free(messages); Don't call free() with possibly corrupted memory. */
    if (sk.daemonize) unlink(sk.pidfile);

    /* Make sure we exit with the right signal at the end. So for instance
     * the core will be dumped if enabled. */
    sigemptyset (&act.sa_mask);
    act.sa_flags = SA_NODEFER | SA_ONSTACK | SA_RESETHAND;
    act.sa_handler = SIG_DFL;
    sigaction (sig, &act, NULL);
    kill(getpid(),sig);
}

