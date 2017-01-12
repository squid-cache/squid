/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _PROFILER_XPROF_TYPE_H_
#define _PROFILER_XPROF_TYPE_H_
/* AUTO-GENERATED FILE */
#if USE_XPROF_STATS
typedef enum {
    XPROF_PROF_UNACCOUNTED,
    XPROF_aclCheckFast,
    XPROF_ACL_matches,
    XPROF_calloc,
    XPROF_clientSocketRecipient,
    XPROF_comm_accept,
    XPROF_comm_check_incoming,
    XPROF_comm_close,
    XPROF_comm_connect_addr,
    XPROF_comm_handle_ready_fd,
    XPROF_commHandleWrite,
    XPROF_comm_open,
    XPROF_comm_poll_normal,
    XPROF_comm_poll_prep_pfds,
    XPROF_comm_read_handler,
    XPROF_comm_udp_sendto,
    XPROF_comm_write_handler,
    XPROF_diskHandleRead,
    XPROF_diskHandleWrite,
    XPROF_esiExpressionEval,
    XPROF_esiParsing,
    XPROF_esiProcessing,
    XPROF_eventRun,
    XPROF_file_close,
    XPROF_file_open,
    XPROF_file_read,
    XPROF_file_write,
    XPROF_free,
    XPROF_free_const,
    XPROF_hash_lookup,
    XPROF_headersEnd,
    XPROF_HttpHeaderClean,
    XPROF_HttpHeader_getCc,
    XPROF_HttpHeaderParse,
    XPROF_HttpMsg_httpMsgParseStep,
    XPROF_HttpParserParseReplyLine,
    XPROF_HttpParserParseReqLine,
    XPROF_httpRequestFree,
    XPROF_HttpServer_parseOneRequest,
    XPROF_httpStart,
    XPROF_HttpStateData_processReplyBody,
    XPROF_HttpStateData_processReplyHeader,
    XPROF_InvokeHandlers,
    XPROF_malloc,
    XPROF_MemBuf_append,
    XPROF_MemBuf_consume,
    XPROF_MemBuf_consumeWhitespace,
    XPROF_MemBuf_grow,
    XPROF_mem_hdr_write,
    XPROF_MemObject_write,
    XPROF_PROF_OVERHEAD,
    XPROF_read,
    XPROF_realloc,
    XPROF_recv,
    XPROF_send,
    XPROF_SignalEngine_checkEvents,
    XPROF_storeClient_kickReads,
    XPROF_storeDirCallback,
    XPROF_StoreEntry_write,
    XPROF_storeGetMemSpace,
    XPROF_storeMaintainSwapSpace,
    XPROF_storeRelease,
    XPROF_StringAllocAndFill,
    XPROF_StringAppend,
    XPROF_StringClean,
    XPROF_StringInitBuf,
    XPROF_StringReset,
    XPROF_write,
    XPROF_xcalloc,
    XPROF_xmalloc,
    XPROF_xrealloc,
    XPROF_LAST
} xprof_type;
#endif
#endif

