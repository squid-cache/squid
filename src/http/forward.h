/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_FORWARD_H
#define SQUID_SRC_HTTP_FORWARD_H

#include "http/one/forward.h"

namespace Http
{

class Stream;
typedef RefCount<Http::Stream> StreamPointer;

} // namespace Http

// TODO move these classes into Http namespace
class HttpRequestMethod;
typedef RefCount<HttpRequestMethod> HttpRequestMethodPointer;

class HttpRequest;
typedef RefCount<HttpRequest> HttpRequestPointer;

class HttpReply;
typedef RefCount<HttpReply> HttpReplyPointer;

#endif /* SQUID_SRC_HTTP_FORWARD_H */

