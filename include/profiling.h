
#ifndef _PROFILING_H_
#define _PROFILING_H_

#include "config.h"

/* forward decls (C++ only) */
#if __cplusplus

class CacheManager;
#endif

#ifdef USE_XPROF_STATS

#if !defined(_SQUID_SOLARIS_)
typedef int64_t  hrtime_t;
#else
#include <sys/time.h>
#endif

#if defined(__i386) || defined(__i386__)
static inline hrtime_t
get_tick(void)
{
    hrtime_t regs;

asm volatile ("rdtsc":"=A" (regs));
    return regs;
    /* We need return value, we rely on CC to optimise out needless subf calls */
    /* Note that "rdtsc" is relatively slow OP and stalls the CPU pipes, so use it wisely */
}

#elif defined(__x86_64) || defined(__x86_64__)
static inline hrtime_t
get_tick(void)
{
    uint32_t lo, hi;
    // Based on an example in Wikipedia
    /* We cannot use "=A", since this would use %rax on x86_64 */
    asm volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return (hrtime_t)hi << 32 | lo;
}

#elif defined(__alpha)
static inline hrtime_t
get_tick(void)
{
    hrtime_t regs;

asm volatile ("rpcc %0" : "=r" (regs));
    return regs;
}

#elif defined(_M_IX86) && defined(_MSC_VER) /* x86 platform on Microsoft C Compiler ONLY */
static __inline hrtime_t
get_tick(void)
{
    hrtime_t regs;

    __asm {
        cpuid
        rdtsc
        mov eax,DWORD PTR regs[0]
        mov edx,DWORD PTR regs[4]
    }
    return regs;
}

#else
#warning Unsupported CPU. Define function get_tick(). Disabling USE_XPROF_STATS...
#undef USE_XPROF_STATS
#endif

#endif /* USE_XPROF_STATS - maybe disabled above */

#ifdef USE_XPROF_STATS

typedef enum {
    XPROF_PROF_UNACCOUNTED,
    XPROF_PROF_OVERHEAD,
    XPROF_hash_lookup,
    XPROF_splay_splay,
    XPROF_xmalloc,
    XPROF_malloc,
    XPROF_xfree,
    XPROF_xxfree,
    XPROF_xrealloc,
    XPROF_xcalloc,
    XPROF_calloc,
    XPROF_xstrdup,
    XPROF_xstrndup,
    XPROF_xstrncpy,
    XPROF_xcountws,
    XPROF_socket,
    XPROF_read,
    XPROF_write,
    XPROF_send,
    XPROF_recv,
    XPROF_sendto,
    XPROF_recvfrom,
    XPROF_accept,
    XPROF_connect,
    XPROF_memPoolChunkNew,
    XPROF_memPoolAlloc,
    XPROF_memPoolFree,
    XPROF_memPoolClean,
    XPROF_aclMatchAclList,
    XPROF_aclCheckFast,
    XPROF_comm_open,
    XPROF_comm_connect_addr,
    XPROF_comm_accept,
    XPROF_comm_close,
    XPROF_comm_udp_sendto,
    XPROF_commHandleWrite,
    XPROF_comm_check_incoming,
    XPROF_comm_poll_prep_pfds,
    XPROF_comm_poll_normal,
    XPROF_comm_handle_ready_fd,
    XPROF_comm_read_handler,
    XPROF_comm_write_handler,
    XPROF_storeGet,
    XPROF_storeMaintainSwapSpace,
    XPROF_storeRelease,
    XPROF_diskHandleWrite,
    XPROF_diskHandleRead,
    XPROF_file_open,
    XPROF_file_read,
    XPROF_file_write,
    XPROF_file_close,
#if USE_SQUID_ESI
    XPROF_esiExpressionEval,
    XPROF_esiProcessing,
    XPROF_esiParsing,
#endif
    XPROF_storeClient_kickReads,
    XPROF_eventRun,
    XPROF_storeDirCallback,
    XPROF_comm_calliocallback,
    XPROF_CommReadCallbackData_callCallback,
    XPROF_CommAcceptCallbackData_callCallback,
    XPROF_CommWriteCallbackData_callCallback,
    XPROF_CommFillCallbackData_callCallback,
    XPROF_HttpStateData_readReply,
    XPROF_HttpStateData_processReplyBody,
    XPROF_StoreEntry_write,
    XPROF_storeGetMemSpace,
    XPROF_MemObject_write,
    XPROF_storeWriteComplete,
    XPROF_mem_hdr_write,
    XPROF_headersEnd,
    XPROF_parseHttpRequest,
    XPROF_HttpStateData_processReplyHeader,
    XPROF_MemBuf_consume,
    XPROF_MemBuf_append,
    XPROF_MemBuf_grow,
    XPROF_InvokeHandlers,
    XPROF_HttpMsg_httpMsgParseStep,
    XPROF_EventDispatcher_dispatch,
    XPROF_SignalDispatcher_dispatch,
    XPROF_Temp1,
    XPROF_Temp2,
    XPROF_Temp3,
    XPROF_clientSocketRecipient,
    XPROF_httpStart,
    XPROF_HttpParserParseReqLine,
    XPROF_httpRequestFree,
    XPROF_HttpHeaderParse,
    XPROF_HttpHeaderClean,
    XPROF_StringInitBuf,
    XPROF_StringInit,
    XPROF_StringLimitInit,
    XPROF_StringClean,
    XPROF_StringReset,
    XPROF_StringAppend,
    XPROF_HttpHeader_findEntry,
    XPROF_HttpHeader_getCc,
    XPROF_HttpHeader_getRange,
    XPROF_checkTimeouts,
    XPROF_CommSelect,
    XPROF_LAST
} xprof_type;

#define XP_NOBEST (hrtime_t)-1

typedef struct _xprof_stats_node xprof_stats_node;

typedef struct _xprof_stats_data xprof_stats_data;

struct _xprof_stats_data
{
    hrtime_t start;
    hrtime_t stop;
    hrtime_t delta;
    hrtime_t best;
    hrtime_t worst;
    hrtime_t count;
    hrtime_t accum;
    int64_t summ;
};

struct _xprof_stats_node
{
    const char *name;
    xprof_stats_data accu;
    xprof_stats_data hist;
};

typedef xprof_stats_node TimersArray[1];

/* public Data */
SQUIDCEXTERN TimersArray *xprof_Timers;

/* Exported functions */
SQUIDCEXTERN void xprof_start(xprof_type type, const char *timer);
SQUIDCEXTERN void xprof_stop(xprof_type type, const char *timer);
SQUIDCEXTERN void xprof_event(void *data);
#if __cplusplus
extern void xprofRegisterWithCacheManager(CacheManager & manager);
#endif

#define PROF_start(type) xprof_start(XPROF_##type, #type)
#define PROF_stop(type) xprof_stop(XPROF_##type, #type)

#else /* USE_XPROF_STATS */

#define PROF_start(ARGS) ((void)0)
#define PROF_stop(ARGS) ((void)0)

#endif /* USE_XPROF_STATS */

#endif /* _PROFILING_H_ */
