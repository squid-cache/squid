/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_FORWARD_H
#define SQUID_SRC_HTTP_FORWARD_H

#include "http/one/forward.h"

#define HTTP_REQBUF_SZ  4096

namespace Http
{

class ContentLengthInterpreter;

class Message;
typedef RefCount<Http::Message> MessagePointer;

class Stream;
typedef RefCount<Http::Stream> StreamPointer;

} // namespace Http

// TODO move these into Http namespace

typedef enum {
    SC_NO_STORE,
    SC_NO_STORE_REMOTE,
    SC_MAX_AGE,
    SC_CONTENT,
    SC_OTHER,
    SC_ENUM_END /* also used to mean "invalid" */
} http_hdr_sc_type;

class HttpHdrSc;

class HttpRequestMethod;

class HttpRequest;
typedef RefCount<HttpRequest> HttpRequestPointer;

class HttpReply;
typedef RefCount<HttpReply> HttpReplyPointer;

#endif /* SQUID_SRC_HTTP_FORWARD_H */

