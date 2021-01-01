/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_ERR_DETAIL_H
#define  _SQUID_ERR_DETAIL_H

typedef enum {
    ERR_DETAIL_NONE,
    ERR_DETAIL_START = 100000, // to avoid clashes with most OS error numbers
    ERR_DETAIL_REDIRECTOR_TIMEDOUT = ERR_DETAIL_START, // External redirector request timed-out
    ERR_DETAIL_CLT_REQMOD_ABORT, // client-facing code detected transaction abort
    ERR_DETAIL_CLT_REQMOD_REQ_BODY, // client-facing code detected REQMOD request body adaptation failure
    ERR_DETAIL_CLT_REQMOD_RESP_BODY, // client-facing code detected REQMOD satisfaction reply body failure
    ERR_DETAIL_SRV_REQMOD_REQ_BODY, // server-facing code detected REQMOD request body abort
    ERR_DETAIL_ICAP_RESPMOD_EARLY, // RESPMOD failed w/o store entry
    ERR_DETAIL_ICAP_RESPMOD_LATE,  // RESPMOD failed with a store entry
    ERR_DETAIL_REQMOD_BLOCK, // REQMOD denied client access
    ERR_DETAIL_RESPMOD_BLOCK_EARLY, // RESPMOD denied client access to HTTP response, before any part of the response was sent
    ERR_DETAIL_RESPMOD_BLOCK_LATE, // RESPMOD denied client access to HTTP response, after [a part of] the response was sent
    ERR_DETAIL_ICAP_XACT_START, // transaction start failure
    ERR_DETAIL_ICAP_XACT_SSL_START, // transaction start failure
    ERR_DETAIL_ICAP_XACT_BODY_CONSUMER_ABORT, // transaction body consumer gone
    ERR_DETAIL_ICAP_INIT_GONE, // initiator gone
    ERR_DETAIL_ICAP_XACT_CLOSE, // ICAP connection closed unexpectedly
    ERR_DETAIL_ICAP_XACT_OTHER, // other ICAP transaction errors
    ERR_DETAIL_EXCEPTION_OTHER, //other errors ( eg std C++ lib errors)
    ERR_DETAIL_MAX,
    ERR_DETAIL_EXCEPTION_START = 110000 // offset for exception ID details
} err_detail_type;

extern const char *err_detail_type_str[];

inline
const char *errorDetailName(int errDetailId)
{
    if (errDetailId < ERR_DETAIL_START)
        return "SYSERR";

    if (errDetailId < ERR_DETAIL_MAX)
        return err_detail_type_str[errDetailId-ERR_DETAIL_START+2];

    if (errDetailId >=ERR_DETAIL_EXCEPTION_START)
        return "EXCEPTION";

    return "UNKNOWN";
}

#endif

